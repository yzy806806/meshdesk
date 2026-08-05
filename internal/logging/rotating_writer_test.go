package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRotatingWriter_BasicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotatingWriter(path, 1<<20, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	data := []byte("hello world\n")
	n, err := w.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("wrote %d bytes, want %d", n, len(data))
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(content) != "hello world\n" {
		t.Fatalf("content = %q, want %q", string(content), "hello world\n")
	}
}

func TestRotatingWriter_Rotation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Small max size to trigger rotation quickly.
	w, err := NewRotatingWriter(path, 50, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Write enough data to trigger multiple rotations.
	for i := 0; i < 10; i++ {
		_, err := w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n"))
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// The current file should exist.
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("current log file missing: %v", err)
	}

	// At least one backup should exist.
	backup1 := path + ".1"
	if _, err := os.Stat(backup1); err != nil {
		t.Fatalf("backup .1 missing: %v", err)
	}

	// Total backups should not exceed maxBackups (3).
	for i := 4; i <= 10; i++ {
		backup := path + "." + string(rune('0'+i))
		if _, err := os.Stat(backup); err == nil {
			t.Fatalf("backup .%d should not exist", i)
		}
	}
}

func TestRotatingWriter_MaxBackupsEnforced(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotatingWriter(path, 10, 2, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Write enough to trigger many rotations.
	for i := 0; i < 20; i++ {
		_, err := w.Write([]byte("XXXXXXXXXX\n"))
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// Only .1 and .2 should exist (maxBackups=2).
	for _, suffix := range []string{".1", ".2"} {
		if _, err := os.Stat(path + suffix); err != nil {
			t.Fatalf("backup %s should exist: %v", suffix, err)
		}
	}
	// .3 and beyond should NOT exist.
	if _, err := os.Stat(path + ".3"); err == nil {
		t.Fatalf("backup .3 should not exist (maxBackups=2)")
	}
}

func TestRotatingWriter_AppendsToExisting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Pre-create a file with some content.
	if err := os.WriteFile(path, []byte("existing line\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	w, err := NewRotatingWriter(path, 1<<20, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	_, err = w.Write([]byte("new line\n"))
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(content)
	if !strings.Contains(s, "existing line") {
		t.Fatalf("existing content lost: %q", s)
	}
	if !strings.Contains(s, "new line") {
		t.Fatalf("new content missing: %q", s)
	}
}

func TestRotatingWriter_Compress(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotatingWriter(path, 20, 3, true)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	// Write enough to trigger rotation.
	for i := 0; i < 5; i++ {
		_, err := w.Write([]byte("CCCCCCCCCCCCCCCCCCCC\n"))
		if err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}

	// The rotated backup should be compressed (.gz).
	backupGz := path + ".1.gz"
	if _, err := os.Stat(backupGz); err != nil {
		t.Fatalf("compressed backup .1.gz should exist: %v", err)
	}

	// The uncompressed backup should NOT exist.
	backupRaw := path + ".1"
	if _, err := os.Stat(backupRaw); err == nil {
		t.Fatalf("uncompressed backup .1 should not exist when compress=true")
	}
}

func TestRotatingWriter_CloseReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w1, err := NewRotatingWriter(path, 1<<20, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	w1.Write([]byte("first session\n"))
	w1.Close()

	// Reopen — should append, not truncate.
	w2, err := NewRotatingWriter(path, 1<<20, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter (reopen): %v", err)
	}
	defer w2.Close()
	w2.Write([]byte("second session\n"))

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	s := string(content)
	if !strings.Contains(s, "first session") {
		t.Fatalf("first session content lost: %q", s)
	}
	if !strings.Contains(s, "second session") {
		t.Fatalf("second session content missing: %q", s)
	}
}

func TestRotatingWriter_Defaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	// Pass zero values — should default to 10MB and 5 backups.
	w, err := NewRotatingWriter(path, 0, 0, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	if w.maxBytes != 10<<20 {
		t.Fatalf("maxBytes = %d, want %d", w.maxBytes, 10<<20)
	}
	if w.maxBackups != 5 {
		t.Fatalf("maxBackups = %d, want 5", w.maxBackups)
	}
}

func TestRotatingWriter_ConcurrentWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.log")

	w, err := NewRotatingWriter(path, 1<<16, 3, false)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	defer w.Close()

	done := make(chan struct{})
	for i := 0; i < 4; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				w.Write([]byte("concurrent write line\n"))
			}
			done <- struct{}{}
		}(i)
	}
	for i := 0; i < 4; i++ {
		<-done
	}

	// Verify the file exists and has content.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Size() == 0 {
		t.Fatalf("log file is empty after concurrent writes")
	}
}
