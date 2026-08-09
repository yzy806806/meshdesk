package update

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// ──────────────────────────────────────────────────────────────────────────
// Update coordinator (T2.2) — one-click node update state machine.
//
// Per node: DISTRIBUTE → VERIFY → BACKUP → REPLACE → RESTART → HEALTH
//            → DONE | ROLLBACK
//
// Dependencies are injected (implemented by the web layer over the
// mesh channel):
//   - FileSvc:   dials a node's FileServer (0x1F4)
//   - CommandSvc: dials a node's CommandServer (0x1F5)
// ──────────────────────────────────────────────────────────────────────────

// FileSvc dials a node's FileServer virtual port.
type FileSvc interface {
	DialFile(ctx context.Context, nodeID string) (io.ReadWriteCloser, error)
}

// CommandSvc dials a node's CommandServer virtual port.
type CommandSvc interface {
	DialCommand(ctx context.Context, nodeID string) (io.ReadWriteCloser, error)
}

// Phase is one step of the per-node update state machine.
type Phase string

const (
	PhaseDistribute Phase = "distribute"
	PhaseVerify     Phase = "verify"
	PhaseBackup     Phase = "backup"
	PhaseReplace    Phase = "replace"
	PhaseRestart    Phase = "restart"
	PhaseHealth     Phase = "health"
	PhaseDone       Phase = "done"
	PhaseRollback   Phase = "rollback"
	PhaseFailed     Phase = "failed"
)

// NodeResult is the outcome for one node.
type NodeResult struct {
	NodeID  string    `json:"node_id"`
	Phase   Phase     `json:"phase"`
	OK      bool      `json:"ok"`
	Message string    `json:"message"`
	Elapsed float64   `json:"elapsed_seconds"`
	Steps   []StepLog `json:"steps"`
}

// StepLog records one state-machine step.
type StepLog struct {
	Phase   Phase  `json:"phase"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail"`
	Elapsed float64
}

// Options configures one update run.
type Options struct {
	// Nodes is the ordered list of peer IDs to update.
	Nodes []string
	// BinaryPath is the local path of the new binary (already uploaded
	// to the Dashboard node).
	BinaryPath string
	// InstallPath is the destination binary path on each node
	// (default /usr/local/bin/meshdesk).
	InstallPath string
	// Service is the systemd unit name (default meshdesk).
	Service string
	// Concurrency caps parallel node updates (default 3).
	Concurrency int
	// RestartDelay waits between restart and health check (default 12s).
	RestartDelay time.Duration
	// ExpectedMD5 optionally verifies the distributed binary.
	ExpectedMD5 string
}

// Coordinator drives updates across nodes.
type Coordinator struct {
	files   FileSvc
	cmds    CommandSvc
	options Options
}

// NewCoordinator creates an update coordinator.
func NewCoordinator(files FileSvc, cmds CommandSvc, options Options) *Coordinator {
	if options.InstallPath == "" {
		options.InstallPath = "/usr/local/bin/meshdesk"
	}
	if options.Service == "" {
		options.Service = "meshdesk"
	}
	if options.Concurrency <= 0 {
		options.Concurrency = 3
	}
	if options.RestartDelay == 0 {
		options.RestartDelay = 12 * time.Second
	}
	return &Coordinator{files: files, cmds: cmds, options: options}
}

// Run updates all nodes. Returns per-node results.
func (c *Coordinator) Run(ctx context.Context) []NodeResult {
	results := make([]NodeResult, 0, len(c.options.Nodes))
	sem := make(chan struct{}, c.options.Concurrency)
	resultCh := make(chan NodeResult, len(c.options.Nodes))

	for _, nodeID := range c.options.Nodes {
		nodeID := nodeID
		go func() {
			sem <- struct{}{}
			defer func() { <-sem }()
			resultCh <- c.updateNode(ctx, nodeID)
		}()
	}
	for range c.options.Nodes {
		results = append(results, <-resultCh)
	}
	return results
}

// updateNode drives one node through the state machine.
func (c *Coordinator) updateNode(ctx context.Context, nodeID string) NodeResult {
	start := time.Now()
	res := NodeResult{NodeID: nodeID}
	steps := []StepLog{}
	addStep := func(p Phase, ok bool, detail string, t0 time.Time) {
		steps = append(steps, StepLog{Phase: p, OK: ok, Detail: detail, Elapsed: time.Since(t0).Seconds()})
	}

	// 1. DISTRIBUTE — write the binary to a staging path.
	t0 := time.Now()
	staging := c.options.InstallPath + ".new"
	if err := c.distribute(ctx, nodeID, staging); err != nil {
		addStep(PhaseDistribute, false, err.Error(), t0)
		res.Phase = PhaseFailed
		res.OK = false
		res.Message = "distribute: " + err.Error()
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	addStep(PhaseDistribute, true, staging, t0)

	// 2. VERIFY — md5 of the staged binary.
	t0 = time.Now()
	md5, err := c.runCmd(ctx, nodeID, fmt.Sprintf("md5sum %s | awk '{print $1}'", staging), 30)
	if err != nil || strings.TrimSpace(md5) == "" {
		addStep(PhaseVerify, false, fmt.Sprintf("md5 failed: %v", err), t0)
		c.rollback(ctx, nodeID, staging, res)
		res.Phase = PhaseFailed
		res.OK = false
		res.Message = "verify: " + err.Error()
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	md5 = strings.TrimSpace(md5)
	if c.options.ExpectedMD5 != "" && md5 != c.options.ExpectedMD5 {
		addStep(PhaseVerify, false, fmt.Sprintf("md5 mismatch: got %s want %s", md5, c.options.ExpectedMD5), t0)
		c.rollback(ctx, nodeID, staging, res)
		res.Phase = PhaseFailed
		res.OK = false
		res.Message = "verify: md5 mismatch"
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	addStep(PhaseVerify, true, md5, t0)

	// 3. BACKUP — copy the current binary aside.
	t0 = time.Now()
	backup := c.options.InstallPath + ".bak"
	if out, err := c.runCmd(ctx, nodeID, fmt.Sprintf("cp -f %s %s 2>&1 || echo 'no existing binary'", c.options.InstallPath, backup), 30); err != nil {
		addStep(PhaseBackup, false, out, t0)
		c.rollback(ctx, nodeID, staging, res)
		res.Phase = PhaseFailed
		res.OK = false
		res.Message = "backup: " + out
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	addStep(PhaseBackup, true, backup, t0)

	// 4. REPLACE — move staged → install, chmod.
	t0 = time.Now()
	if out, err := c.runCmd(ctx, nodeID, fmt.Sprintf("chmod +x %s && mv -f %s %s && sync", staging, staging, c.options.InstallPath), 30); err != nil {
		addStep(PhaseReplace, false, out, t0)
		c.rollback(ctx, nodeID, staging, res)
		res.Phase = PhaseFailed
		res.OK = false
		res.Message = "replace: " + out
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	addStep(PhaseReplace, true, c.options.InstallPath, t0)

	// 5. RESTART — systemctl restart (or kill+start fallback).
	t0 = time.Now()
	if out, err := c.runCmd(ctx, nodeID, fmt.Sprintf("systemctl restart %s 2>&1 || (pkill -9 -f %s 2>/dev/null; systemctl start %s 2>&1)", c.options.Service, c.options.InstallPath, c.options.Service), 30); err != nil {
		addStep(PhaseRestart, false, out, t0)
		c.rollback(ctx, nodeID, staging, res)
		res.Phase = PhaseFailed
		res.OK = false
		res.Message = "restart: " + out
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	addStep(PhaseRestart, true, c.options.Service, t0)

	// 6. HEALTH — wait, verify the process is up.
	t0 = time.Now()
	time.Sleep(c.options.RestartDelay)
	healthOut, healthErr := c.runCmd(ctx, nodeID, fmt.Sprintf("pgrep -f %s >/dev/null && echo UP || echo DOWN", c.options.InstallPath), 15)
	if healthErr != nil || !strings.Contains(healthOut, "UP") {
		addStep(PhaseHealth, false, fmt.Sprintf("health: %s (%v)", healthOut, healthErr), t0)
		// 7. ROLLBACK — restore backup + restart.
		rbOut, rbErr := c.runCmd(ctx, nodeID, fmt.Sprintf("cp -f %s %s && systemctl restart %s 2>&1", backup, c.options.InstallPath, c.options.Service), 30)
		addStep(PhaseRollback, rbErr == nil, fmt.Sprintf("restore %s: %s", backup, rbOut), t0)
		res.Phase = PhaseRollback
		res.OK = false
		res.Message = "health check failed, rolled back"
		res.Steps = steps
		res.Elapsed = time.Since(start).Seconds()
		return res
	}
	addStep(PhaseHealth, true, healthOut, t0)

	res.Phase = PhaseDone
	res.OK = true
	res.Message = "update complete"
	res.Steps = steps
	res.Elapsed = time.Since(start).Seconds()
	return res
}

// distribute writes the local binary to the node's staging path.
func (c *Coordinator) distribute(ctx context.Context, nodeID, destPath string) error {
	conn, err := c.files.DialFile(ctx, nodeID)
	if err != nil {
		return fmt.Errorf("dial file: %w", err)
	}
	defer conn.Close()

	f, err := os.Open(c.options.BinaryPath)
	if err != nil {
		return fmt.Errorf("open local binary: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}

	if err := json.NewEncoder(conn).Encode(map[string]any{
		"op": "write", "path": destPath, "size": info.Size(),
	}); err != nil {
		return err
	}
	if _, err := io.CopyN(conn, f, info.Size()); err != nil {
		return fmt.Errorf("stream binary: %w", err)
	}
	var resp struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Written int64  `json:"written"`
	}
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		return err
	}
	if !resp.OK {
		return fmt.Errorf("fileserver: %s", resp.Error)
	}
	if resp.Written != info.Size() {
		return fmt.Errorf("short write: %d/%d", resp.Written, info.Size())
	}
	return nil
}

// runCmd executes a command on the node and returns stdout.
func (c *Coordinator) runCmd(ctx context.Context, nodeID, cmd string, timeoutSec int) (string, error) {
	conn, err := c.cmds.DialCommand(ctx, nodeID)
	if err != nil {
		return "", fmt.Errorf("dial command: %w", err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(map[string]any{
		"cmd": cmd, "timeout": timeoutSec,
	}); err != nil {
		return "", err
	}
	var resp struct {
		OK     bool   `json:"ok"`
		Error  string `json:"error"`
		Stdout string `json:"stdout"`
		Stderr string `json:"stderr"`
		Exit   int    `json:"exit"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", err
	}
	if !resp.OK {
		return resp.Stdout + resp.Stderr, fmt.Errorf("command error: %s", resp.Error)
	}
	if resp.Exit != 0 {
		return resp.Stdout + resp.Stderr, fmt.Errorf("exit %d", resp.Exit)
	}
	return resp.Stdout, nil
}

// rollback removes the staging file on failure before the replace step.
func (c *Coordinator) rollback(ctx context.Context, nodeID, staging string, res NodeResult) {
	c.runCmd(ctx, nodeID, fmt.Sprintf("rm -f %s", staging), 10)
}
