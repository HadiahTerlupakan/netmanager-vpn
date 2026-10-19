// Package store keeps the service's state in SQLite. Key columns hold values
// already sealed by the caller; the store never sees plaintext keys.
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound is returned when a row does not exist (or is released).
	ErrNotFound = errors.New("store: not found")
	// ErrConflict is returned when a unique constraint rejects an insert, such as
	// an address already held by a live row.
	ErrConflict = errors.New("store: conflict")
	// ErrInUse is returned when a row cannot be deleted because others reference it.
	ErrInUse = errors.New("store: in use")
)

// Store is a handle on the SQLite database.
type Store struct {
	db *sql.DB
}

// migrations are applied in order and never edited once released; schema
// changes append a new entry.
var migrations = []string{
	`CREATE TABLE server_keys (
		iface TEXT PRIMARY KEY,
		private_key TEXT NOT NULL
	);
	CREATE TABLE hubs (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL,
		public_host TEXT NOT NULL,
		listen_port INTEGER NOT NULL,
		backhaul_addr TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		private_key TEXT NOT NULL,
		api_token TEXT NOT NULL,
		status TEXT NOT NULL,
		join_expires_at TEXT NOT NULL,
		last_seen_at TEXT,
		created_at TEXT NOT NULL
	);
	CREATE TABLE routers (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL,
		ref TEXT NOT NULL,
		address TEXT NOT NULL,
		public_key TEXT NOT NULL,
		private_key TEXT NOT NULL,
		status TEXT NOT NULL,
		created_at TEXT NOT NULL,
		released_at TEXT
	);
	CREATE UNIQUE INDEX routers_live_address ON routers (address) WHERE released_at IS NULL;
	CREATE TABLE router_hubs (
		router_id TEXT NOT NULL,
		hub_id TEXT NOT NULL,
		priority INTEGER NOT NULL,
		sync_state TEXT NOT NULL,
		PRIMARY KEY (router_id, hub_id)
	);
	CREATE INDEX router_hubs_hub ON router_hubs (hub_id);
	CREATE TABLE router_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		router_id TEXT NOT NULL,
		from_hub_id TEXT NOT NULL,
		to_hub_id TEXT NOT NULL,
		at TEXT NOT NULL
	);
	CREATE INDEX router_events_router ON router_events (router_id, at);
	CREATE TABLE admin_peers (
		id TEXT PRIMARY KEY,
		label TEXT NOT NULL,
		address TEXT NOT NULL UNIQUE,
		public_key TEXT NOT NULL,
		private_key TEXT NOT NULL,
		created_at TEXT NOT NULL
	);
	CREATE TABLE hub_config (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		core_public_key TEXT NOT NULL,
		core_endpoint TEXT NOT NULL,
		backhaul_addr TEXT NOT NULL,
		api_token TEXT NOT NULL,
		private_key_up TEXT NOT NULL,
		private_key_nm TEXT NOT NULL
	);
	CREATE TABLE peers (
		public_key TEXT PRIMARY KEY,
		address TEXT NOT NULL,
		created_at TEXT NOT NULL
	);`,
}

// Open opens (creating if needed) the database at path and applies pending
// migrations. A single connection serializes writers so WAL never reports
// SQLITE_BUSY between this process's own goroutines.
func Open(path string) (*Store, error) {
	dsn := "file:" + path +
		"?_pragma=journal_mode(WAL)&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open: %w", err)
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the database.
func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY)`); err != nil {
		return fmt.Errorf("store: migrations table: %w", err)
	}
	var current int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&current); err != nil {
		return fmt.Errorf("store: read version: %w", err)
	}
	if current > len(migrations) {
		return fmt.Errorf("store: database schema version %d is newer than this build knows (%d)", current, len(migrations))
	}
	for i := current; i < len(migrations); i++ {
		if err := s.applyMigration(i+1, migrations[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) applyMigration(version int, stmt string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(stmt); err != nil {
		return fmt.Errorf("store: migration %d: %w", version, err)
	}
	if _, err := tx.Exec(`INSERT INTO schema_migrations (version) VALUES (?)`, version); err != nil {
		return err
	}
	return tx.Commit()
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("store: crypto/rand: " + err.Error())
	}
	return hex.EncodeToString(b)
}

// Times are stored as fixed-width UTC text so they sort lexically.
const timeLayout = "2006-01-02T15:04:05.000000000Z"

func fmtTime(t time.Time) string { return t.UTC().Format(timeLayout) }

func fmtTimePtr(t *time.Time) any {
	if t == nil {
		return nil
	}
	return fmtTime(*t)
}

func parseTime(s string) (time.Time, error) {
	return time.ParseInLocation(timeLayout, s, time.UTC)
}

func parseTimePtr(ns sql.NullString) (*time.Time, error) {
	if !ns.Valid {
		return nil, nil
	}
	t, err := parseTime(ns.String)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func parseAddr(s string) (netip.Addr, error) { return netip.ParseAddr(s) }

// conflictOr maps a unique-constraint violation to ErrConflict so callers can
// tell a collision from an I/O failure.
func conflictOr(err error) error {
	if err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return ErrConflict
	}
	return err
}

// affected maps a zero-row UPDATE/DELETE to ErrNotFound.
func affected(res sql.Result, err error) error {
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// BackupTo writes a consistent copy of the database to path. VACUUM INTO is
// used instead of copying the file because the live database is in WAL mode,
// where a plain copy can miss pages still in the -wal file. path must not exist.
func (s *Store) BackupTo(path string) error {
	if _, err := s.db.Exec(`VACUUM INTO ?`, path); err != nil {
		return fmt.Errorf("store: backup: %w", err)
	}
	return nil
}
