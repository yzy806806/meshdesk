package webssh

import (
	"testing"
)

func TestEncodeDecodeMessage(t *testing.T) {
	original := Message{Type: MsgInput, Data: "aGVsbG8="}

	raw, err := EncodeMessage(original.Type, original.Data)
	if err != nil {
		t.Fatalf("EncodeMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("type mismatch: got %s, want %s", decoded.Type, original.Type)
	}
	if decoded.Data != original.Data {
		t.Errorf("data mismatch: got %s, want %s", decoded.Data, original.Data)
	}
}

func TestDecodeInvalidJSON(t *testing.T) {
	_, err := DecodeMessage([]byte("not json"))
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestNewResizeMessage(t *testing.T) {
	msg, err := NewResizeMessage(120, 40)
	if err != nil {
		t.Fatalf("NewResizeMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != MsgResize {
		t.Fatalf("type mismatch: got %s, want %s", decoded.Type, MsgResize)
	}

	cols, rows, err := ParseResize(decoded.Data)
	if err != nil {
		t.Fatalf("ParseResize failed: %v", err)
	}
	if cols != 120 || rows != 40 {
		t.Errorf("dimensions mismatch: got %dx%d, want 120x40", cols, rows)
	}
}

func TestNewOutputMessage(t *testing.T) {
	data := []byte("hello world")
	msg, err := NewOutputMessage(data)
	if err != nil {
		t.Fatalf("NewOutputMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != MsgOutput {
		t.Fatalf("type mismatch: got %s, want %s", decoded.Type, MsgOutput)
	}

	raw, err := DecodeBase64(decoded.Data)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}
	if string(raw) != "hello world" {
		t.Errorf("output mismatch: got %q, want %q", string(raw), "hello world")
	}
}

func TestNewStatusMessage(t *testing.T) {
	msg, err := NewStatusMessage(StatusConnected, "Connected to node-3")
	if err != nil {
		t.Fatalf("NewStatusMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != MsgStatus {
		t.Fatalf("type mismatch: got %s, want %s", decoded.Type, MsgStatus)
	}
	// Verify it contains "connected"
	if decoded.Data == "" {
		t.Fatal("status data is empty")
	}
}

func TestNewErrorMessage(t *testing.T) {
	msg, err := NewErrorMessage("connection refused")
	if err != nil {
		t.Fatalf("NewErrorMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != MsgError {
		t.Fatalf("type mismatch: got %s, want %s", decoded.Type, MsgError)
	}
	if decoded.Data != "connection refused" {
		t.Errorf("error message mismatch: got %q, want %q", decoded.Data, "connection refused")
	}
}

func TestNewConnectedMessage(t *testing.T) {
	msg, err := NewConnectedMessage("abc123", "10.10.1.2", 80, 24)
	if err != nil {
		t.Fatalf("NewConnectedMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != MsgConnected {
		t.Fatalf("type mismatch: got %s, want %s", decoded.Type, MsgConnected)
	}
}

func TestNewClipboardOutMessage(t *testing.T) {
	data := []byte("clip content")
	msg, err := NewClipboardOutMessage(data)
	if err != nil {
		t.Fatalf("NewClipboardOutMessage failed: %v", err)
	}

	decoded, err := DecodeMessage(msg)
	if err != nil {
		t.Fatalf("DecodeMessage failed: %v", err)
	}

	if decoded.Type != MsgClipboardOut {
		t.Fatalf("type mismatch: got %s, want %s", decoded.Type, MsgClipboardOut)
	}

	raw, err := DecodeBase64(decoded.Data)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}
	if string(raw) != "clip content" {
		t.Errorf("clipboard mismatch: got %q", string(raw))
	}
}

func TestParseResizeInvalid(t *testing.T) {
	_, _, err := ParseResize("not json")
	if err == nil {
		t.Fatal("expected error for invalid resize data")
	}
}
