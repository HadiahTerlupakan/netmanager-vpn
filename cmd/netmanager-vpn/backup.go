package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	backupPattern   = "state-*.db"
	backupStamp     = "20060102-150405"
	backupRetention = 7 * 24 * time.Hour
)

// backup snapshots the state database into dir and prunes snapshots past the
// retention window. Pruning runs only after the new snapshot is written, so a
// failing backup never shrinks the set of copies.
func backup(dir string, now time.Time) error {
	statePath := os.Getenv("NMVPN_STATE")
	if statePath == "" {
		statePath = defaultState
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(statePath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.BackupTo(filepath.Join(dir, "state-"+now.UTC().Format(backupStamp)+".db")); err != nil {
		return err
	}
	return pruneBackups(dir, now)
}

func pruneBackups(dir string, now time.Time) error {
	files, err := filepath.Glob(filepath.Join(dir, backupPattern))
	if err != nil {
		return err
	}
	for _, f := range files {
		info, err := os.Stat(f)
		if err != nil {
			return err
		}
		if now.Sub(info.ModTime()) > backupRetention {
			if err := os.Remove(f); err != nil {
				return fmt.Errorf("prune %s: %w", f, err)
			}
		}
	}
	return nil
}
