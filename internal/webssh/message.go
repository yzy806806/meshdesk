// Package webssh implements the browser-based SSH terminal bridge.
//
// Architecture (ARCHITECTURE.md Decision C):
//
//	Browser                    Web Server Node               Target Node
//	┌──────────┐              ┌────────────────┐            ┌──────────────┐
//	│ xterm.js │──WebSocket──│  WebSocket Hub  │──SSH over──│  SSH Server   │
//	│  (+addons)│             │  (goroutine-    │  mesh VPN │  (x/crypto/ssh)│
//	│          │              │   per-session)  │           │       │       │
//	└──────────┘              └────────────────┘           │  creack/pty   │
//	                                                       │       │       │
//	                                                       │   /bin/bash   │
//	                                                       └───────────────┘
//
// The WebSocket message protocol is JSON-based with a "type" discriminator.
// All messages are JSON objects sent as WebSocket text frames.
package webssh

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// MsgType is the discriminator for WebSocket messages.
type MsgType string

const (
	// Client → Server messages

	MsgInput     MsgType = "input"     // keystrokes from the browser terminal
	MsgResize    MsgType = "resize"    // terminal dimensions changed (SIGWINCH)
	MsgClipboard MsgType = "clipboard" // paste content from browser clipboard
	MsgClose     MsgType = "close"     // client explicitly closing the session

	// Server → Client messages

	MsgOutput       MsgType = "output"        // PTY output to display in the terminal
	MsgStatus       MsgType = "status"        // connection state update (status bar)
	MsgClipboardOut MsgType = "clipboard_out" // clipboard content from remote (OSC 52)
	MsgError        MsgType = "error"         // error message (fatal)
	MsgConnected    MsgType = "connected"     // session successfully established
)

// SessionStatus represents the connection state shown in the status bar.
type SessionStatus string

const (
	StatusConnecting   SessionStatus = "connecting"   // dialing target SSH server
	StatusConnected    SessionStatus = "connected"    // SSH session active, PTY allocated
	StatusDisconnected SessionStatus = "disconnected" // session ended (network or client)
	StatusError        SessionStatus = "error"        // session failed to start or errored
)

// Message is the envelope for all WebSocket communication.
// The "data" field is interpreted differently per message type:
//   - input/output/clipboard: base64-encoded raw bytes
//   - resize: JSON-encoded {cols, rows}
//   - status: JSON-encoded {status, message}
//   - error: plain text string
//   - connected: JSON-encoded {peer_id, mesh_ip, cols, rows}
type Message struct {
	Type MsgType `json:"type"`
	Data string  `json:"data,omitempty"`
}

// ResizeData is the payload for resize messages.
type ResizeData struct {
	Cols int `json:"cols"`
	Rows int `json:"rows"`
}

// StatusData is the payload for status messages.
type StatusData struct {
	Status  SessionStatus `json:"status"`
	Message string        `json:"message,omitempty"`
	PeerID  string        `json:"peer_id,omitempty"`
	MeshIP  string        `json:"mesh_ip,omitempty"`
}

// ConnectedData is sent when a session is fully established.
type ConnectedData struct {
	PeerID string `json:"peer_id"`
	MeshIP string `json:"mesh_ip"`
	Cols   int    `json:"cols"`
	Rows   int    `json:"rows"`
}

// EncodeMessage builds a JSON message envelope.
func EncodeMessage(typ MsgType, data string) ([]byte, error) {
	return json.Marshal(Message{Type: typ, Data: data})
}

// DecodeMessage parses a JSON message envelope.
func DecodeMessage(raw []byte) (Message, error) {
	var msg Message
	if err := json.Unmarshal(raw, &msg); err != nil {
		return Message{}, fmt.Errorf("decode websocket message: %w", err)
	}
	return msg, nil
}

// NewResizeMessage creates a resize message.
func NewResizeMessage(cols, rows int) ([]byte, error) {
	rd := ResizeData{Cols: cols, Rows: rows}
	data, err := json.Marshal(rd)
	if err != nil {
		return nil, fmt.Errorf("marshal resize data: %w", err)
	}
	return EncodeMessage(MsgResize, string(data))
}

// NewStatusMessage creates a status bar message.
func NewStatusMessage(status SessionStatus, message string) ([]byte, error) {
	sd := StatusData{Status: status, Message: message}
	data, err := json.Marshal(sd)
	if err != nil {
		return nil, fmt.Errorf("marshal status data: %w", err)
	}
	return EncodeMessage(MsgStatus, string(data))
}

// NewOutputMessage creates an output message from raw bytes.
// The bytes are base64-encoded in the Data field.
func NewOutputMessage(data []byte) ([]byte, error) {
	return EncodeMessage(MsgOutput, base64.StdEncoding.EncodeToString(data))
}

// NewConnectedMessage creates a connected message.
func NewConnectedMessage(peerID, meshIP string, cols, rows int) ([]byte, error) {
	cd := ConnectedData{PeerID: peerID, MeshIP: meshIP, Cols: cols, Rows: rows}
	data, err := json.Marshal(cd)
	if err != nil {
		return nil, fmt.Errorf("marshal connected data: %w", err)
	}
	return EncodeMessage(MsgConnected, string(data))
}

// NewErrorMessage creates an error message.
func NewErrorMessage(message string) ([]byte, error) {
	return EncodeMessage(MsgError, message)
}

// NewClipboardOutMessage creates a clipboard-out message (OSC 52 from remote).
func NewClipboardOutMessage(data []byte) ([]byte, error) {
	return EncodeMessage(MsgClipboardOut, base64.StdEncoding.EncodeToString(data))
}

// ParseResize parses the data field of a resize message.
func ParseResize(data string) (cols, rows int, err error) {
	var rd ResizeData
	if err := json.Unmarshal([]byte(data), &rd); err != nil {
		return 0, 0, fmt.Errorf("parse resize data: %w", err)
	}
	return rd.Cols, rd.Rows, nil
}

// DecodeBase64 decodes a base64 string to raw bytes.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}
