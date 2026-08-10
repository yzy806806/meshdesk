// Command meshfsput: test smux-channel file write reliability over a
// lossy link. Dials the target peer's FileServer (0x1F4) directly via
// the mesh node (no web API / step-up), writes a payload, then prints
// the result so the caller can verify the remote md5.
//
// Usage: meshfsput <config.yaml> <peer_pubkey> <remote_path> <local_file>
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"github.com/yzy806806/meshdesk/internal/config"
	"github.com/yzy806806/meshdesk/internal/mesh"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Fprintln(os.Stderr, "usage: meshfsput <config> <peer_pubkey> <remote_path> <local_file>")
		os.Exit(1)
	}
	cfgPath, peerKey, remotePath, localFile := os.Args[1], os.Args[2], os.Args[3], os.Args[4]

	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	// This tool is a test client — no monitoring pushes.
	cfg.Monitoring.Collectors = nil
	// Avoid binding the port the running daemon already holds.
	if cfg.Mesh.Port == 52888 || cfg.Mesh.GossipPort == 52888 {
		cfg.Mesh.Port = 52889
		cfg.Mesh.GossipPort = 52889
	}

	node, err := mesh.New(cfg)
	if err != nil {
		log.Fatalf("new node: %v", err)
	}
	if err := node.Start(); err != nil {
		log.Fatalf("start node: %v", err)
	}
	defer node.Close()

	// Dial the configured static peers (like main.go does).
	for _, pc := range cfg.Peers {
		if pc.Endpoint == "" {
			continue
		}
		if err := node.AddPeer(pc); err != nil {
			log.Printf("AddPeer %s: %v", pc.Endpoint, err)
		}
	}

	// Wait for the peer session (up to 60s).
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if node.HasActiveSession(peerKey) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if !node.HasActiveSession(peerKey) {
		log.Fatalf("no session for peer %s", peerKey[:16])
	}
	log.Printf("session active with %s", peerKey[:16])

	f, err := os.Open(localFile)
	if err != nil {
		log.Fatalf("open local: %v", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		log.Fatalf("stat: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	conn, err := node.DialVirtualPort(ctx, peerKey, mesh.FileVirtualPort)
	if err != nil {
		log.Fatalf("dial file port: %v", err)
	}
	defer conn.Close()

	start := time.Now()
	if err := json.NewEncoder(conn).Encode(map[string]any{
		"op": "write", "path": remotePath, "size": info.Size(),
	}); err != nil {
		log.Fatalf("send req: %v", err)
	}
	if _, err := io.Copy(conn, f); err != nil {
		log.Fatalf("stream payload: %v", err)
	}
	var resp struct {
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Written int64  `json:"written"`
	}
	if err := json.NewDecoder(io.LimitReader(conn, 64<<10)).Decode(&resp); err != nil {
		log.Fatalf("read resp: %v", err)
	}
	elapsed := time.Since(start)
	if !resp.OK {
		log.Fatalf("fileserver: %s", resp.Error)
	}
	fmt.Printf("RESULT ok=true written=%d expected=%d elapsed=%.1fs throughput=%.1f KB/s\n",
		resp.Written, info.Size(), elapsed.Seconds(), float64(resp.Written)/elapsed.Seconds()/1024)
	if resp.Written != info.Size() {
		fmt.Println("RESULT mismatch: short write")
		os.Exit(2)
	}
}
