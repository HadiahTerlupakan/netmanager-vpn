package store

import (
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func mode(t *testing.T, path string) fs.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// The database holds sealed keys and, on a hub, the plaintext API token, so
// nothing but the service's own user may read it or its backups.
func TestOpenAndBackupKeepStatePrivate(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if got := mode(t, dir); got != 0o700 {
		t.Fatalf("state dir mode %o", got)
	}
	if got := mode(t, path); got != 0o600 {
		t.Fatalf("state db mode %o", got)
	}
	backup := filepath.Join(t.TempDir(), "copy.db")
	if err := s.BackupTo(backup); err != nil {
		t.Fatal(err)
	}
	if got := mode(t, backup); got != 0o600 {
		t.Fatalf("backup mode %o", got)
	}
}
