package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPruneBackupsKeepsSevenDaysAndOtherFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 10, 19, 3, 15, 0, 0, time.UTC)
	for name, age := range map[string]time.Duration{
		"state-old.db":   8 * 24 * time.Hour,
		"state-edge.db":  6*24*time.Hour + 23*time.Hour,
		"state-new.db":   time.Hour,
		"other-old.db":   30 * 24 * time.Hour,
		"state-old.db-x": 30 * 24 * time.Hour,
	} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	if err := pruneBackups(dir, now); err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]bool{
		"state-old.db": false, "state-edge.db": true, "state-new.db": true,
		"other-old.db": true, "state-old.db-x": true,
	} {
		_, err := os.Stat(filepath.Join(dir, name))
		if (err == nil) != want {
			t.Errorf("%s exists=%v, want %v", name, err == nil, want)
		}
	}
}

func TestBackupWritesSnapshot(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("NMVPN_STATE", filepath.Join(dir, "state.db"))
	out := filepath.Join(dir, "bk")
	if err := backup(out, time.Date(2026, 10, 19, 3, 15, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(out, "state-20261019-031500.db")); err != nil {
		t.Fatal(err)
	}
}
