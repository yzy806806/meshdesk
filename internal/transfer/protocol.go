// Package transfer implements the file transfer protocol for MeshDesk.
//
// Protocol (ARCHITECTURE.md Decision F):
//
//	┌─────────────────┐         ┌─────────────────┐
//	│  Sender (web    │         │  Receiver       │
//	│  server node)   │         │  (target node)  │
//	│                 │         │                 │
//	│  1. Open conn   │────────▶│  2. Accept      │
//	│  3. Send header │────────▶│  4. Read header │
//	│  5. Send data   │────────▶│  5. Read data   │
//	│  6. Wait ACK   │◀────────│  7. Send ACK    │
//	│  8. Close       │         │  9. Close       │
//	└─────────────────┘         └─────────────────┘
//
// The protocol uses a simple framing: a 4-byte big-endian length header
// for the JSON metadata, followed by the raw file bytes. An ACK/NACK
// message is sent back as a JSON response.
//
// All transfers ride over the mesh VPN (gVisor netstack), so the
// transport is already encrypted by WireGuard. The capability layer
// (auth package) enforces that only authorized peers can initiate or
// accept transfers.
package transfer

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"
)

// ProtocolVersion is the file transfer protocol version.
const ProtocolVersion = 1

// DefaultChunkSize is the default size for streaming reads/writes.
const DefaultChunkSize = 64 * 1024 // 64 KB

// DefaultTimeout is the default I/O timeout for transfer operations.
const DefaultTimeout = 300 * time.Second

// DefaultMaxFileSize is the default maximum file size for incoming transfers
// (1 GB). Used when no explicit limit is configured.
const DefaultMaxFileSize int64 = 1 << 30

// FileType enumerates the types of transfers supported.
type FileType string

const (
	FileTypeRegular   FileType = "regular"
	FileTypeDirectory FileType = "directory" // future: recursive directory transfer
)

// FileHeader is the JSON metadata sent before the file bytes.
// It contains all information needed to decide whether to accept
// the transfer and where to write it, before any data is sent.
type FileHeader struct {
	Version   int      `json:"version"`
	Filename  string   `json:"filename"`
	Size      int64    `json:"size"`
	Mode      uint32   `json:"mode"` // file permissions (e.g. 0644)
	FileType  FileType `json:"file_type"`
	ModTime   string   `json:"mod_time"`           // RFC3339
	Checksum  string   `json:"checksum,omitempty"` // hex SHA-256 (optional, v1.1)
	SrcPeerID string   `json:"src_peer_id"`        // requesting peer identity
}

// TransferResult is the ACK/NACK sent back from the receiver.
type TransferResult struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
	Bytes   int64  `json:"bytes_written,omitempty"`
}

// Send writes a file to the given connection using the file transfer protocol.
// The conn is typically a mesh VPN connection (net.Conn) which is both
// readable and writable.
//
// If the connection implements net.Conn, SetDeadline is called with the
// DefaultTimeout to prevent indefinite hangs on stalled peers.
//
// Steps:
//  1. Marshal FileHeader as JSON
//  2. Write 4-byte big-endian length prefix
//  3. Write JSON header bytes
//  4. Stream file contents (computing SHA-256 if header.Checksum is empty)
//  5. Read ACK/NACK from the connection (readable side)
//
// If checksum is provided in the header, the receiver can verify integrity.
func Send(conn io.ReadWriter, reader io.Reader, header *FileHeader) (*TransferResult, error) {
	return SendWithContext(context.Background(), conn, reader, header)
}

// SendWithContext is like Send but with a context for cancellation.
// If the context has a deadline, it is applied to the connection (if it
// implements net.Conn) alongside the DefaultTimeout, whichever is sooner.
func SendWithContext(ctx context.Context, conn io.ReadWriter, reader io.Reader, header *FileHeader) (*TransferResult, error) {
	if header.Version == 0 {
		header.Version = ProtocolVersion
	}

	// Apply deadline to the connection if possible.
	applyDeadline(ctx, conn)

	// Marshal header
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}

	// Write 4-byte length prefix
	headerLen := uint32(len(headerJSON))
	if err := binary.Write(conn, binary.BigEndian, headerLen); err != nil {
		return nil, fmt.Errorf("write header length: %w", err)
	}

	// Write header JSON
	if _, err := conn.Write(headerJSON); err != nil {
		return nil, fmt.Errorf("write header: %w", err)
	}

	// Stream file data, computing SHA-256 if not already set
	if header.FileType == FileTypeRegular && header.Size > 0 {
		var writer io.Writer = conn
		var hasher hash.Hash
		if header.Checksum == "" {
			hasher = sha256.New()
			writer = io.MultiWriter(conn, hasher)
		}
		copied, err := io.Copy(writer, reader)
		if err != nil {
			return nil, fmt.Errorf("write file data: %w", err)
		}
		if copied != header.Size {
			return nil, fmt.Errorf("short write: wrote %d, expected %d", copied, header.Size)
		}
		// If we computed a checksum, fill it in (the receiver will verify)
		if hasher != nil {
			header.Checksum = hex.EncodeToString(hasher.Sum(nil))
		}
	}

	// Read ACK — the response is also framed with a 4-byte length prefix
	result, err := readFramedJSON[TransferResult](conn)
	if err != nil {
		return nil, fmt.Errorf("read ack: %w", err)
	}

	return result, nil
}

// Receive reads a file transfer from the connection using the protocol.
// destDir is the base directory where the file will be written. The
// filename is sanitized to prevent path traversal.
//
// The conn must be both readable and writable (typically a net.Conn
// over the mesh VPN). The receiver reads the header and data, then
// sends back an ACK/NACK on the same connection.
//
// If the FileHeader contains a Checksum (SHA-256 hex), it is verified
// after the file is written. A mismatch results in a NACK and the
// file is deleted.
//
// The file size is checked against DefaultMaxFileSize before any data
// is read. Use ReceiveWithMaxSize for a custom limit.
//
// Returns the FileHeader that was received and the number of bytes written.
func Receive(conn io.ReadWriter, destDir string) (*FileHeader, int64, error) {
	return ReceiveWithMaxSize(context.Background(), conn, destDir, DefaultMaxFileSize)
}

// ReceiveWithContext is like Receive but with a context for cancellation.
func ReceiveWithContext(ctx context.Context, conn io.ReadWriter, destDir string) (*FileHeader, int64, error) {
	return ReceiveWithMaxSize(ctx, conn, destDir, DefaultMaxFileSize)
}

// ReceiveWithMaxSize is like ReceiveWithContext but accepts a custom
// maximum file size. If maxFileSize is 0, no size limit is enforced
// (not recommended for production). If the header declares a size
// exceeding the limit, the transfer is rejected before any file data
// is read, and a NACK with the configured limit is sent back.
func ReceiveWithMaxSize(ctx context.Context, conn io.ReadWriter, destDir string, maxFileSize int64) (*FileHeader, int64, error) {
	// Apply deadline to the connection if possible.
	applyDeadline(ctx, conn)

	// Read 4-byte header length
	header, err := readFramedJSON[FileHeader](conn)
	if err != nil {
		// Send NACK
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("header read: %v", err)})
		return nil, 0, fmt.Errorf("read header: %w", err)
	}

	if header.Version != ProtocolVersion {
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("unsupported protocol version %d", header.Version)})
		return header, 0, fmt.Errorf("unsupported protocol version %d", header.Version)
	}

	// Enforce max file size before reading any data (Gap 4 fix).
	// This prevents disk exhaustion from oversized or malicious transfers.
	if maxFileSize > 0 && header.Size > maxFileSize {
		msg := fmt.Sprintf("file size %d exceeds maximum %d", header.Size, maxFileSize)
		sendResult(conn, TransferResult{OK: false, Message: msg})
		return header, 0, fmt.Errorf("transfer rejected: %s", msg)
	}

	// Sanitize filename to prevent path traversal
	safeName := sanitizeFilename(header.Filename)
	if safeName == "" {
		sendResult(conn, TransferResult{OK: false, Message: "invalid filename"})
		return header, 0, fmt.Errorf("invalid filename after sanitization")
	}

	// Ensure destination directory exists
	if err := os.MkdirAll(destDir, 0755); err != nil {
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("mkdir: %v", err)})
		return header, 0, fmt.Errorf("create dest dir: %w", err)
	}

	destPath := filepath.Join(destDir, safeName)

	// For directories, just create the directory
	if header.FileType == FileTypeDirectory {
		if err := os.MkdirAll(destPath, os.FileMode(header.Mode)); err != nil {
			sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("mkdir: %v", err)})
			return header, 0, fmt.Errorf("create directory: %w", err)
		}
		sendResult(conn, TransferResult{OK: true, Message: "directory created"})
		return header, 0, nil
	}

	// Create the destination file
	f, err := os.OpenFile(destPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
	if err != nil {
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("create file: %v", err)})
		return header, 0, fmt.Errorf("create dest file: %w", err)
	}

	// Copy file data, limited to header.Size bytes. If a checksum is
	// present in the header, compute SHA-256 as we read.
	var hasher hash.Hash
	var writer io.Writer = f
	if header.Checksum != "" {
		hasher = sha256.New()
		writer = io.MultiWriter(f, hasher)
	}

	limited := io.LimitReader(conn, header.Size)
	copied, err := io.Copy(writer, limited)
	if err != nil {
		f.Close()
		os.Remove(destPath) // clean up partial file
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("write data: %v", err)})
		return header, copied, fmt.Errorf("write file data: %w", err)
	}

	if copied != header.Size {
		f.Close()
		os.Remove(destPath)
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("short read: got %d, expected %d", copied, header.Size)})
		return header, copied, fmt.Errorf("short read: got %d, expected %d", copied, header.Size)
	}

	// Close the file before setting times / verifying checksum
	if err := f.Close(); err != nil {
		sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("close file: %v", err)})
		return header, copied, fmt.Errorf("close dest file: %w", err)
	}

	// Set modification time if provided
	if header.ModTime != "" {
		if modTime, err := time.Parse(time.RFC3339, header.ModTime); err == nil {
			os.Chtimes(destPath, modTime, modTime)
		}
	}

	// Verify checksum if present
	if header.Checksum != "" && hasher != nil {
		computed := hex.EncodeToString(hasher.Sum(nil))
		if computed != header.Checksum {
			os.Remove(destPath) // delete corrupted file
			sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("checksum mismatch: computed %s, expected %s", computed, header.Checksum)})
			return header, 0, fmt.Errorf("checksum mismatch: computed %s, expected %s", computed, header.Checksum)
		}
	}

	// Send ACK
	sendResult(conn, TransferResult{OK: true, Bytes: copied})
	return header, copied, nil
}

// MakeFileHeader creates a FileHeader from a local file path.
// Reads file info and opens the file for streaming. The caller is
// responsible for closing the returned file handle.
//
// The SHA-256 checksum is computed over the file contents and stored
// in the Checksum field so the receiver can verify integrity.
func MakeFileHeader(path string, srcPeerID string) (*FileHeader, *os.File, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, fmt.Errorf("stat file: %w", err)
	}

	if info.IsDir() {
		return &FileHeader{
			Version:   ProtocolVersion,
			Filename:  filepath.Base(path),
			Size:      0,
			Mode:      uint32(info.Mode().Perm()),
			FileType:  FileTypeDirectory,
			ModTime:   info.ModTime().Format(time.RFC3339),
			SrcPeerID: srcPeerID,
		}, nil, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open file: %w", err)
	}

	// Compute SHA-256 checksum
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("compute checksum: %w", err)
	}
	checksum := hex.EncodeToString(h.Sum(nil))

	// Seek back to start for streaming
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("seek file: %w", err)
	}

	return &FileHeader{
		Version:   ProtocolVersion,
		Filename:  filepath.Base(path),
		Size:      info.Size(),
		Mode:      uint32(info.Mode().Perm()),
		FileType:  FileTypeRegular,
		ModTime:   info.ModTime().Format(time.RFC3339),
		Checksum:  checksum,
		SrcPeerID: srcPeerID,
	}, f, nil
}

// readFramedJSON reads a 4-byte length-prefixed JSON message.
// T is the type to unmarshal into. This is generic to support both
// FileHeader and TransferResult reads.
func readFramedJSON[T any](r io.Reader) (*T, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, fmt.Errorf("read length: %w", err)
	}
	if length > 1<<20 { // 1 MB max for JSON metadata
		return nil, fmt.Errorf("header too large: %d bytes", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, fmt.Errorf("read json: %w", err)
	}
	var result T
	if err := json.Unmarshal(buf, &result); err != nil {
		return nil, fmt.Errorf("unmarshal json: %w", err)
	}
	return &result, nil
}

// sendResult writes a TransferResult as a framed JSON message.
func sendResult(w io.Writer, result TransferResult) {
	data, err := json.Marshal(result)
	if err != nil {
		return
	}
	binary.Write(w, binary.BigEndian, uint32(len(data)))
	w.Write(data)
}

// sanitizeFilename prevents path traversal attacks by stripping
// directory separators, parent references, and other dangerous characters.
// Only the base filename is kept; if the result is empty or "." or "..",
// returns empty string (caller should reject).
func sanitizeFilename(name string) string {
	if name == "" {
		return ""
	}
	// Get the base name, stripping any directory components
	base := filepath.Base(name)
	// Reject dangerous names
	if base == "." || base == ".." || base == "" {
		return ""
	}
	// Reject hidden files starting with . (optional security measure)
	// We allow them — just ensure no path separators
	if base != name {
		// The input had path separators; we keep only the base
		return base
	}
	return base
}

// applyDeadline sets a deadline on the connection if it implements net.Conn.
// It uses the DefaultTimeout if the context has no deadline, or whichever
// is sooner between the context deadline and DefaultTimeout.
func applyDeadline(ctx context.Context, conn io.ReadWriter) {
	nc, ok := conn.(interface {
		SetDeadline(t time.Time) error
	})
	if !ok {
		return
	}

	deadline := time.Now().Add(DefaultTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	nc.SetDeadline(deadline)
}

// AuthChecker is the interface for capability-based authorization of
// incoming file transfers. In production this is implemented by
// wrapping *auth.CapabilityEngine. The receiver calls AuthorizeFileTransfer
// before accepting any file data, enforcing Decision E (zero-trust).
type AuthChecker interface {
	// AuthorizeFileTransfer checks whether sourcePeer is authorized to
	// transfer files. Returns true if allowed, false otherwise.
	// Every call should produce an audit log entry.
	AuthorizeFileTransfer(sourcePeer string) bool
}

// Receiver listens on a mesh-internal port and accepts incoming file
// transfers. Each incoming connection is handled in a goroutine that
// calls Receive to read the file and write it to the destination directory.
//
// The receiver enforces:
//   - Path traversal prevention via sanitizeFilename
//   - File size limits via maxFileSize (Gap 4)
//   - Capability checks via authChecker (Gap 2 — Decision E compliance)
//
// If authChecker is nil, all transfers are accepted (for testing only).
// In production, always set an authChecker.
type Receiver struct {
	listener    MeshListener
	port        int
	destDir     string
	maxFileSize int64
	authChecker AuthChecker
	stopCh      chan struct{}
}

// MeshListener abstracts mesh-internal listening.
type MeshListener interface {
	ListenMesh(port int) (net.Listener, error)
}

// NewReceiver creates a file transfer receiver that writes incoming
// files to destDir. Uses the default max file size (1 GB).
func NewReceiver(listener MeshListener, port int, destDir string) *Receiver {
	return &Receiver{
		listener:    listener,
		port:        port,
		destDir:     destDir,
		maxFileSize: DefaultMaxFileSize,
		stopCh:      make(chan struct{}),
	}
}

// NewReceiverWithAuth creates a file transfer receiver with capability
// enforcement and a custom max file size. The authChecker is called
// for every incoming transfer to verify the source peer has the
// file_transfer capability (Decision E compliance).
func NewReceiverWithAuth(listener MeshListener, port int, destDir string, maxFileSize int64, authChecker AuthChecker) *Receiver {
	if maxFileSize == 0 {
		maxFileSize = DefaultMaxFileSize
	}
	return &Receiver{
		listener:    listener,
		port:        port,
		destDir:     destDir,
		maxFileSize: maxFileSize,
		authChecker: authChecker,
		stopCh:      make(chan struct{}),
	}
}

// Start begins accepting incoming file transfers.
func (r *Receiver) Start() error {
	ln, err := r.listener.ListenMesh(r.port)
	if err != nil {
		return fmt.Errorf("listen on mesh port %d: %w", r.port, err)
	}

	go func() {
		<-r.stopCh
		ln.Close()
	}()

	go r.acceptLoop(ln)
	return nil
}

// Stop halts the receiver.
func (r *Receiver) Stop() {
	select {
	case <-r.stopCh:
	default:
		close(r.stopCh)
	}
}

func (r *Receiver) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-r.stopCh:
				return
			default:
				continue
			}
		}
		go r.handleConn(conn)
	}
}

func (r *Receiver) handleConn(conn net.Conn) {
	defer conn.Close()

	// If an auth checker is configured, read the header first to extract
	// the source peer ID, then authorize before accepting any file data.
	// This implements Decision E: unauthorized transfers are rejected
	// before touching the filesystem.
	if r.authChecker != nil {
		// We need to read the header to get SrcPeerID, but ReceiveWithMaxSize
		// reads the header internally. To avoid duplicating logic, we use a
		// peeking approach: read the framed header, check auth, then pass
		// a combined reader (header bytes + remaining conn) to Receive.
		header, headerBytes, err := peekFileHeader(conn)
		if err != nil {
			sendResult(conn, TransferResult{OK: false, Message: fmt.Sprintf("header read: %v", err)})
			return
		}

		// Authorize the source peer for file_transfer capability.
		if !r.authChecker.AuthorizeFileTransfer(header.SrcPeerID) {
			sendResult(conn, TransferResult{OK: false, Message: "unauthorized: file_transfer capability denied"})
			return
		}

		// Re-create a reader that presents the header bytes followed by
		// the remaining connection data, so ReceiveWithMaxSize can re-read
		// the header seamlessly.
		combined := newPrefixReader(headerBytes, conn)
		_, _, err = ReceiveWithMaxSize(context.Background(), combined, r.destDir, r.maxFileSize)
		if err != nil {
			return
		}
		return
	}

	// No auth checker — use ReceiveWithMaxSize directly (testing mode).
	_, _, err := ReceiveWithMaxSize(context.Background(), conn, r.destDir, r.maxFileSize)
	if err != nil {
		// Error is already sent as NACK to the sender; just log locally.
		return
	}
}

// peekFileHeader reads the framed JSON header from conn without consuming
// the rest of the stream. Returns the parsed header and the raw bytes
// that were read (length prefix + JSON), so the caller can reconstruct
// the stream by prepending these bytes.
func peekFileHeader(conn net.Conn) (*FileHeader, []byte, error) {
	// Read the 4-byte length prefix
	var length uint32
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
		return nil, nil, fmt.Errorf("read length: %w", err)
	}
	if length > 1<<20 {
		return nil, nil, fmt.Errorf("header too large: %d bytes", length)
	}

	// Read the JSON header body
	jsonBuf := make([]byte, length)
	if _, err := io.ReadFull(conn, jsonBuf); err != nil {
		return nil, nil, fmt.Errorf("read json: %w", err)
	}

	// Parse the header
	var header FileHeader
	if err := json.Unmarshal(jsonBuf, &header); err != nil {
		return nil, nil, fmt.Errorf("unmarshal json: %w", err)
	}

	// Reconstruct the raw framed bytes (length prefix + JSON)
	raw := make([]byte, 4+length)
	binary.BigEndian.PutUint32(raw[:4], length)
	copy(raw[4:], jsonBuf)

	return &header, raw, nil
}

// prefixReader wraps an io.Reader by prepending a fixed byte buffer.
// Reads first drain the prefix, then delegate to the underlying reader.
// This is used to reconstruct a stream after peeking at the header.
type prefixReader struct {
	prefix []byte
	offset int
	rest   io.Reader
}

func newPrefixReader(prefix []byte, rest io.Reader) *prefixReader {
	return &prefixReader{prefix: prefix, rest: rest}
}

func (pr *prefixReader) Read(p []byte) (int, error) {
	if pr.offset < len(pr.prefix) {
		n := copy(p, pr.prefix[pr.offset:])
		pr.offset += n
		return n, nil
	}
	return pr.rest.Read(p)
}

// Ensure prefixReader satisfies io.Reader
var _ io.Reader = (*prefixReader)(nil)

// Ensure prefixReader satisfies io.ReadWriter via the underlying conn
// (writes go through to conn when prefix is exhausted). We need this
// because ReceiveWithMaxSize writes ACK/NACK back through the same conn.
func (pr *prefixReader) Write(p []byte) (int, error) {
	type writer interface{ Write([]byte) (int, error) }
	w, ok := pr.rest.(writer)
	if !ok {
		return 0, fmt.Errorf("underlying reader is not writable")
	}
	return w.Write(p)
}

// Ensure prefixReader satisfies io.ReadWriter
var _ io.ReadWriter = (*prefixReader)(nil)
