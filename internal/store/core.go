package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

const hubCols = `id, name, public_host, listen_port, backhaul_addr, public_key, private_key,
	api_token, status, join_expires_at, last_seen_at, created_at, ipsec_psk, protocols`

type scanner interface{ Scan(dest ...any) error }

func scanHub(r scanner) (Hub, error) {
	var h Hub
	var addr, joinExp, created, protocols string
	var seen sql.NullString
	err := r.Scan(&h.ID, &h.Name, &h.PublicHost, &h.ListenPort, &addr, &h.PublicKey,
		&h.PrivateKey, &h.APIToken, &h.Status, &joinExp, &seen, &created, &h.IPsecPSK, &protocols)
	if err != nil {
		return Hub{}, err
	}
	if h.BackhaulAddr, err = parseAddr(addr); err != nil {
		return Hub{}, err
	}
	if h.JoinExpiresAt, err = parseTime(joinExp); err != nil {
		return Hub{}, err
	}
	if h.LastSeenAt, err = parseTimePtr(seen); err != nil {
		return Hub{}, err
	}
	h.Protocols = splitProtocols(protocols)
	h.CreatedAt, err = parseTime(created)
	return h, err
}

// CreateHub stores h under a fresh ID and returns the stored row.
func (s *Store) CreateHub(h Hub) (Hub, error) {
	h.ID = newID()
	h.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO hubs (`+hubCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		h.ID, h.Name, h.PublicHost, h.ListenPort, h.BackhaulAddr.String(), h.PublicKey,
		h.PrivateKey, h.APIToken, h.Status, fmtTime(h.JoinExpiresAt), fmtTimePtr(h.LastSeenAt),
		fmtTime(h.CreatedAt), h.IPsecPSK, joinProtocols(h.Protocols))
	if err != nil {
		return Hub{}, conflictOr(err)
	}
	return s.GetHub(h.ID)
}

// GetHub returns the hub or ErrNotFound.
func (s *Store) GetHub(id string) (Hub, error) {
	h, err := scanHub(s.db.QueryRow(`SELECT `+hubCols+` FROM hubs WHERE id = ?`, id))
	if err == sql.ErrNoRows {
		return Hub{}, ErrNotFound
	}
	return h, err
}

// ListHubs returns all hubs, oldest first.
func (s *Store) ListHubs() ([]Hub, error) {
	rows, err := s.db.Query(`SELECT ` + hubCols + ` FROM hubs ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Hub
	for rows.Next() {
		h, err := scanHub(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// UpdateHubStatus sets the hub's status; lastSeenAt is left untouched when nil.
func (s *Store) UpdateHubStatus(id, status string, lastSeenAt *time.Time) error {
	return affected(s.db.Exec(
		`UPDATE hubs SET status = ?, last_seen_at = COALESCE(?, last_seen_at) WHERE id = ?`,
		status, fmtTimePtr(lastSeenAt), id))
}

// UpdateHubKeys replaces the hub's keypair and token when its join is re-issued.
func (s *Store) UpdateHubKeys(id, publicKey, sealedPrivateKey, apiToken string, joinExpiresAt time.Time) error {
	return affected(s.db.Exec(
		`UPDATE hubs SET public_key = ?, private_key = ?, api_token = ?, join_expires_at = ? WHERE id = ?`,
		publicKey, sealedPrivateKey, apiToken, fmtTime(joinExpiresAt), id))
}

// UpdateHubPSK stores the hub's IPsec pre-shared key, already sealed.
func (s *Store) UpdateHubPSK(id, sealedPSK string) error {
	return affected(s.db.Exec(`UPDATE hubs SET ipsec_psk = ? WHERE id = ?`, sealedPSK, id))
}

// UpdateHubProtocols records which protocols the hub serves. An empty list is
// refused: a hub that serves nothing cannot be told apart from a stale row.
func (s *Store) UpdateHubProtocols(id string, protocols []string) error {
	if len(protocols) == 0 {
		return errors.New("store: hub protocols must not be empty")
	}
	return affected(s.db.Exec(`UPDATE hubs SET protocols = ? WHERE id = ?`, joinProtocols(protocols), id))
}

const protocolWireGuard = "wireguard"

// orWireGuard applies the column default to a caller that left the protocol unset.
func orWireGuard(p string) string {
	if p == "" {
		return protocolWireGuard
	}
	return p
}

func joinProtocols(p []string) string {
	if len(p) == 0 {
		return protocolWireGuard
	}
	return strings.Join(p, ",")
}

func splitProtocols(s string) []string {
	if s == "" {
		return []string{protocolWireGuard}
	}
	return strings.Split(s, ",")
}

// DeleteHub removes a hub, or returns ErrInUse while any router lists it.
func (s *Store) DeleteHub(id string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM router_hubs WHERE hub_id = ?`, id).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ErrInUse
	}
	if err := affected(tx.Exec(`DELETE FROM hubs WHERE id = ?`, id)); err != nil {
		return err
	}
	return tx.Commit()
}

// SetServerKey stores the sealed private key of a core interface.
func (s *Store) SetServerKey(iface, sealedPrivateKey string) error {
	_, err := s.db.Exec(`INSERT INTO server_keys (iface, private_key) VALUES (?, ?)
		ON CONFLICT(iface) DO UPDATE SET private_key = excluded.private_key`, iface, sealedPrivateKey)
	return err
}

// ServerKey returns the sealed private key of a core interface.
func (s *Store) ServerKey(iface string) (string, error) {
	var k string
	err := s.db.QueryRow(`SELECT private_key FROM server_keys WHERE iface = ?`, iface).Scan(&k)
	if err == sql.ErrNoRows {
		return "", ErrNotFound
	}
	return k, err
}
