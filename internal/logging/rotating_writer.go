// Package logging provides a rotating file writer for the standard
// library log package. It implements io.WriteCloser and can be passed
// to log.SetOutput.
//
// When the current log file exceeds MaxBytes, it is rotated:
// the current file becomes <file>.1, <file>.1 becomes <file>.2, etc.
// At most MaxBackups rotated files are kept; older ones are deleted.
// Optionally, rotated files are compressed with gzip.
package logging

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// RotatingWriter is an io.WriteCloser that writes to a file and
// rotates it when it exceeds MaxBytes. It is safe for concurrent use.
type RotatingWriter struct {
	mu sync.Mutex

	dir       string
	baseName  string
	maxBytes  int64
	maxBackups int
	maxAge    int    // days; 0 = no age-based deletion
	compress  bool

	currentFile *os.File
	currentSize int64
}

// NewRotatingWriter creates a new RotatingWriter that writes to
// the file at path. If the file already exists, it is appended to.
// If maxBytes <= 0, defaults to 10 MB. If maxBackups <= 0, defaults to 5.
func NewRotatingWriter(path string, maxBytes int64, maxBackups int, compress bool) (*RotatingWriter, error) {
	if maxBytes <= 0 {
		maxBytes = 10 << 20
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}

	dir := filepath.Dir(path)
	baseName := filepath.Base(path)

	// Ensure the directory exists.
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, fmt.Errorf("create log directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, fmt.Errorf("open log file %s: %w", path, err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat log file %s: %w", path, err)
	}

	return &RotatingWriter{
		dir:         dir,
		baseName:    baseName,
		maxBytes:    maxBytes,
		maxBackups:  maxBackups,
		compress:    compress,
		currentFile: f,
		currentSize: info.Size(),
	}, nil
}

// Write writes p to the current log file. If the file exceeds
// maxBytes after the write, rotation is triggered.
func (w *RotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.currentFile == nil {
		return 0, fmt.Errorf("rotating writer: no file open")
	}

	n, err := w.currentFile.Write(p)
	if err != nil {
		return n, err
	}
	w.currentSize += int64(n)

	if w.currentSize >= w.maxBytes {
		w.rotateLocked()
	}
	return n, nil
}

// Close closes the current log file.
func (w *RotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.currentFile != nil {
		err := w.currentFile.Close()
		w.currentFile = nil
		return err
	}
	return nil
}

// rotateLocked performs the rotation. The caller must hold w.mu.
func (w *RotatingWriter) rotateLocked() {
	if w.currentFile != nil {
		_ = w.currentFile.Close()
		w.currentFile = nil
	}

	// Delete the oldest backup if it exists.
	oldest := filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.baseName, w.maxBackups))
	if w.compress {
		oldest = oldest + ".gz"
	}
	_ = os.Remove(oldest)

	// Shift backups: .(N-1) -> .N, ..., .1 -> .2
	for i := w.maxBackups - 1; i >= 1; i-- {
		src := filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.baseName, i))
		dst := filepath.Join(w.dir, fmt.Sprintf("%s.%d", w.baseName, i+1))

		// Try uncompressed first, then compressed.
		if _, err := os.Stat(src); err == nil {
			_ = os.Rename(src, dst)
			continue
		}
		srcGz := src + ".gz"
		dstGz := dst + ".gz"
		if _, err := os.Stat(srcGz); err == nil {
			_ = os.Rename(srcGz, dstGz)
		}
	}

	// Rotate current file -> .1
	current := filepath.Join(w.dir, w.baseName)
	rotated := filepath.Join(w.dir, w.baseName+".1")
	_ = os.Rename(current, rotated)

	// Compress the rotated file if enabled.
	if w.compress {
		if err := compressFile(rotated); err == nil {
			_ = os.Remove(rotated)
		}
	}

	// Open a fresh current file.
	f, err := os.OpenFile(current, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		// This is bad — we can't open the log file. Write to stderr
		// as a fallback and hope the operator notices.
		fmt.Fprintf(os.Stderr, "rotating writer: failed to open new log file: %v\n", err)
		return
	}
	w.currentFile = f
	w.currentSize = 0

	// Clean up old files by age.
	if w.maxAge > 0 {
		w.removeOldFilesLocked()
	}
}

// removeOldFilesLocked removes rotated backup files older than maxAge days.
func (w *RotatingWriter) removeOldFilesLocked() {
	cutoff := time.Now().AddDate(0, 0, -w.maxAge)
	for i := 1; i <= w.maxBackups; i++ {
		for _, suffix := range []string{"", ".gz"} {
			path := filepath.Join(w.dir, fmt.Sprintf("%s.%d%s", w.baseName, i, suffix))
			info, err := os.Stat(path)
			if err != nil {
				continue
			}
			if info.ModTime().Before(cutoff) {
				_ = os.Remove(path)
			}
		}
	}
}

// SetMaxAge sets the maximum age in days for rotated log files.
// Files older than this are deleted on the next rotation.
// Set to 0 to disable age-based deletion.
func (w *RotatingWriter) SetMaxAge(days int) {
	w.mu.Lock()
	w.maxAge = days
	w.mu.Unlock()
}

// compressFile compresses the file at src into src + ".gz" and
// returns nil on success.
func compressFile(src string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(src + ".gz")
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return nil
}
