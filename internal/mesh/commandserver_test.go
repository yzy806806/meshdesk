package mesh

import (
	"encoding/json"
	"net"
	"testing"
	"time"
)

// runCommandConn pairs the CommandServer handler with a client over
// net.Pipe.
func runCommandConn(t *testing.T, req CommandRequest) CommandResponse {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	cs := &CommandServer{}
	done := make(chan struct{})
	go func() {
		cs.handle(server)
		close(done)
	}()

	if err := json.NewEncoder(client).Encode(req); err != nil {
		t.Fatalf("send req: %v", err)
	}
	var resp CommandResponse
	if err := json.NewDecoder(client).Decode(&resp); err != nil {
		t.Fatalf("decode resp: %v", err)
	}
	<-done
	return resp
}

// TestCommandServer_Echo runs a simple command.
func TestCommandServer_Echo(t *testing.T) {
	resp := runCommandConn(t, CommandRequest{Cmd: "echo hello-mesh"})
	if !resp.OK || resp.Stdout != "hello-mesh\n" {
		t.Fatalf("echo failed: %+v", resp)
	}
}

// TestCommandServer_ExitCode captures non-zero exit codes.
func TestCommandServer_ExitCode(t *testing.T) {
	resp := runCommandConn(t, CommandRequest{Cmd: "exit 3"})
	if !resp.OK || resp.Exit != 3 {
		t.Fatalf("exit code failed: %+v", resp)
	}
}

// TestCommandServer_Stderr captures stderr.
func TestCommandServer_Stderr(t *testing.T) {
	resp := runCommandConn(t, CommandRequest{Cmd: "echo err-msg 1>&2"})
	if !resp.OK || resp.Stderr != "err-msg\n" {
		t.Fatalf("stderr failed: %+v", resp)
	}
}

// TestCommandServer_Timeout kills long-running commands.
func TestCommandServer_Timeout(t *testing.T) {
	start := time.Now()
	resp := runCommandConn(t, CommandRequest{Cmd: "sleep 10", Timeout: 1})
	if time.Since(start) > 5*time.Second {
		t.Fatalf("command not killed by timeout: %+v", resp)
	}
	if !resp.OK {
		t.Fatalf("timeout should still return ok (killed), got %+v", resp)
	}
}

// TestCommandServer_EmptyRejects empty commands.
func TestCommandServer_EmptyRejects(t *testing.T) {
	resp := runCommandConn(t, CommandRequest{Cmd: ""})
	if resp.OK {
		t.Fatalf("empty command should be rejected")
	}
}
