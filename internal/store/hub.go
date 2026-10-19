package store

import (
	"database/sql"
	"time"
)

// SaveHubConfig writes the hub's single configuration row, replacing any prior one.
func (s *Store) SaveHubConfig(c HubConfig) error {
	_, err := s.db.Exec(`INSERT INTO hub_config
		(id, core_public_key, core_endpoint, backhaul_addr, listen_port, api_token, private_key_up, private_key_nm)
		VALUES (1,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET core_public_key = excluded.core_public_key,
			core_endpoint = excluded.core_endpoint, backhaul_addr = excluded.backhaul_addr,
			listen_port = excluded.listen_port,
			api_token = excluded.api_token, private_key_up = excluded.private_key_up,
			private_key_nm = excluded.private_key_nm`,
		c.CorePublicKey, c.CoreEndpoint, c.BackhaulAddr.String(), c.ListenPort, c.APIToken,
		c.PrivateKeyUp, c.PrivateKeyNM)
	return err
}

// LoadHubConfig returns the hub's configuration, or ErrNotFound before it has joined.
func (s *Store) LoadHubConfig() (HubConfig, error) {
	var c HubConfig
	var addr string
	err := s.db.QueryRow(`SELECT core_public_key, core_endpoint, backhaul_addr, listen_port, api_token,
		private_key_up, private_key_nm FROM hub_config WHERE id = 1`).
		Scan(&c.CorePublicKey, &c.CoreEndpoint, &addr, &c.ListenPort, &c.APIToken, &c.PrivateKeyUp, &c.PrivateKeyNM)
	if err == sql.ErrNoRows {
		return HubConfig{}, ErrNotFound
	}
	if err != nil {
		return HubConfig{}, err
	}
	c.BackhaulAddr, err = parseAddr(addr)
	return c, err
}

// UpsertPeer adds a router peer or updates its address, keeping created_at.
func (s *Store) UpsertPeer(p Peer) error {
	_, err := s.db.Exec(`INSERT INTO peers (public_key, address, created_at) VALUES (?,?,?)
		ON CONFLICT(public_key) DO UPDATE SET address = excluded.address`,
		p.PublicKey, p.Address.String(), fmtTime(time.Now()))
	return err
}

// DeletePeer removes a peer; removing one that is absent is not an error, since
// the core retries removals until the hub confirms.
func (s *Store) DeletePeer(publicKey string) error {
	_, err := s.db.Exec(`DELETE FROM peers WHERE public_key = ?`, publicKey)
	return err
}

// ListPeers returns all peers, oldest first.
func (s *Store) ListPeers() ([]Peer, error) {
	rows, err := s.db.Query(`SELECT public_key, address, created_at FROM peers ORDER BY created_at, public_key`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Peer
	for rows.Next() {
		var p Peer
		var addr, created string
		if err := rows.Scan(&p.PublicKey, &addr, &created); err != nil {
			return nil, err
		}
		if p.Address, err = parseAddr(addr); err != nil {
			return nil, err
		}
		if p.CreatedAt, err = parseTime(created); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
