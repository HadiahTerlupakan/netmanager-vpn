package store

import "time"

// CreateAdminPeer stores p under a fresh ID and returns the stored row.
func (s *Store) CreateAdminPeer(p AdminPeer) (AdminPeer, error) {
	p.ID = newID()
	p.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO admin_peers (id, label, address, public_key, private_key, created_at)
		VALUES (?,?,?,?,?,?)`, p.ID, p.Label, p.Address.String(), p.PublicKey, p.PrivateKey,
		fmtTime(p.CreatedAt))
	return p, err
}

// ListAdminPeers returns all admin peers, oldest first.
func (s *Store) ListAdminPeers() ([]AdminPeer, error) {
	rows, err := s.db.Query(`SELECT id, label, address, public_key, private_key, created_at
		FROM admin_peers ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AdminPeer
	for rows.Next() {
		var p AdminPeer
		var addr, created string
		if err := rows.Scan(&p.ID, &p.Label, &addr, &p.PublicKey, &p.PrivateKey, &created); err != nil {
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

// DeleteAdminPeer removes the peer, or returns ErrNotFound.
func (s *Store) DeleteAdminPeer(id string) error {
	return affected(s.db.Exec(`DELETE FROM admin_peers WHERE id = ?`, id))
}
