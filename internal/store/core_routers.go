package store

import (
	"database/sql"
	"fmt"
	"net/netip"
	"time"
)

const routerCols = `id, label, ref, address, public_key, private_key, status, created_at, released_at`

func scanRouter(r scanner) (Router, error) {
	var rt Router
	var addr, created string
	var released sql.NullString
	err := r.Scan(&rt.ID, &rt.Label, &rt.Ref, &addr, &rt.PublicKey, &rt.PrivateKey,
		&rt.Status, &created, &released)
	if err != nil {
		return Router{}, err
	}
	if rt.Address, err = parseAddr(addr); err != nil {
		return Router{}, err
	}
	if rt.CreatedAt, err = parseTime(created); err != nil {
		return Router{}, err
	}
	rt.ReleasedAt, err = parseTimePtr(released)
	return rt, err
}

// CreateRouter stores r under a fresh ID and returns the stored row.
func (s *Store) CreateRouter(r Router) (Router, error) {
	r.ID = newID()
	r.CreatedAt = time.Now().UTC()
	_, err := s.db.Exec(`INSERT INTO routers (`+routerCols+`) VALUES (?,?,?,?,?,?,?,?,NULL)`,
		r.ID, r.Label, r.Ref, r.Address.String(), r.PublicKey, r.PrivateKey, r.Status,
		fmtTime(r.CreatedAt))
	if err != nil {
		return Router{}, conflictOr(err)
	}
	return s.GetRouter(r.ID)
}

// GetRouter returns an unreleased router or ErrNotFound.
func (s *Store) GetRouter(id string) (Router, error) {
	r, err := scanRouter(s.db.QueryRow(
		`SELECT `+routerCols+` FROM routers WHERE id = ? AND released_at IS NULL`, id))
	if err == sql.ErrNoRows {
		return Router{}, ErrNotFound
	}
	return r, err
}

// ListRouters returns unreleased routers, oldest first.
func (s *Store) ListRouters() ([]Router, error) {
	rows, err := s.db.Query(
		`SELECT ` + routerCols + ` FROM routers WHERE released_at IS NULL ORDER BY created_at, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Router
	for rows.Next() {
		r, err := scanRouter(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ClaimRouter marks a pending router as claimed by its device and records the
// device's ref; any other router (already active, released, unknown) yields
// ErrNotFound.
func (s *Store) ClaimRouter(id, ref string) error {
	return affected(s.db.Exec(
		`UPDATE routers SET status = ?, ref = ? WHERE id = ? AND status = ? AND released_at IS NULL`,
		RouterStatusActive, ref, id, RouterStatusPending))
}

// DeleteRouter soft-deletes a router: the row stays with released_at set so its
// address is not handed out again while the old nas.nasname may still exist.
func (s *Store) DeleteRouter(id string) error {
	return s.releaseRouter(id, "")
}

// DeleteRouterIfPending is DeleteRouter that refuses a router claimed in the
// meantime (ErrNotFound), so expiry cannot remove a router just brought up.
func (s *Store) DeleteRouterIfPending(id string) error {
	return s.releaseRouter(id, RouterStatusPending)
}

func (s *Store) releaseRouter(id, onlyStatus string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	err = affected(tx.Exec(`UPDATE routers SET released_at = ? WHERE id = ? AND released_at IS NULL
		AND (? = '' OR status = ?)`, fmtTime(time.Now()), id, onlyStatus, onlyStatus))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM router_hubs WHERE router_id = ?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// requireRowsExist rejects a router that is released or unknown and any unknown
// hub, so no orphan router_hubs row can pin a hub against deletion.
func requireRowsExist(tx *sql.Tx, routerID string, hubIDs []string) error {
	var n int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM routers WHERE id = ? AND released_at IS NULL`, routerID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	for _, hub := range hubIDs {
		if err := tx.QueryRow(`SELECT COUNT(*) FROM hubs WHERE id = ?`, hub).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return ErrNotFound
		}
	}
	return nil
}

// SetRouterHubs replaces the router's ordered hub list (priority is the index).
// Hubs that stay keep their sync_state; new ones start as "pending".
func (s *Store) SetRouterHubs(routerID string, hubIDs []string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := requireRowsExist(tx, routerID, hubIDs); err != nil {
		return err
	}
	old := map[string]string{}
	rows, err := tx.Query(`SELECT hub_id, sync_state FROM router_hubs WHERE router_id = ?`, routerID)
	if err != nil {
		return err
	}
	for rows.Next() {
		var hub, state string
		if err := rows.Scan(&hub, &state); err != nil {
			rows.Close()
			return err
		}
		old[hub] = state
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM router_hubs WHERE router_id = ?`, routerID); err != nil {
		return err
	}
	for i, hub := range hubIDs {
		state, ok := old[hub]
		if !ok {
			state = SyncStatePending
		}
		if _, err := tx.Exec(`INSERT INTO router_hubs (router_id, hub_id, priority, sync_state)
			VALUES (?,?,?,?)`, routerID, hub, i, state); err != nil {
			return fmt.Errorf("store: router %s hub %s: %w", routerID, hub, err)
		}
	}
	return tx.Commit()
}

// ListRouterHubs returns the router's hubs in priority order.
func (s *Store) ListRouterHubs(routerID string) ([]RouterHub, error) {
	rows, err := s.db.Query(`SELECT router_id, hub_id, priority, sync_state FROM router_hubs
		WHERE router_id = ? ORDER BY priority`, routerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouterHub
	for rows.Next() {
		var rh RouterHub
		if err := rows.Scan(&rh.RouterID, &rh.HubID, &rh.Priority, &rh.SyncState); err != nil {
			return nil, err
		}
		out = append(out, rh)
	}
	return out, rows.Err()
}

// UpdateRouterHubSyncState records whether the hub has the router's peer.
func (s *Store) UpdateRouterHubSyncState(routerID, hubID, state string) error {
	return affected(s.db.Exec(
		`UPDATE router_hubs SET sync_state = ? WHERE router_id = ? AND hub_id = ?`,
		state, routerID, hubID))
}

// AddRouterEvent records a hub change; fromHubID is empty for a first assignment.
func (s *Store) AddRouterEvent(routerID, fromHubID, toHubID string, at time.Time) error {
	_, err := s.db.Exec(`INSERT INTO router_events (router_id, from_hub_id, to_hub_id, at)
		VALUES (?,?,?,?)`, routerID, fromHubID, toHubID, fmtTime(at))
	return err
}

// ListRouterEvents returns up to limit events, newest first.
func (s *Store) ListRouterEvents(routerID string, limit int) ([]RouterEvent, error) {
	rows, err := s.db.Query(`SELECT id, router_id, from_hub_id, to_hub_id, at FROM router_events
		WHERE router_id = ? ORDER BY at DESC, id DESC LIMIT ?`, routerID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RouterEvent
	for rows.Next() {
		var e RouterEvent
		var at string
		if err := rows.Scan(&e.ID, &e.RouterID, &e.FromHubID, &e.ToHubID, &at); err != nil {
			return nil, err
		}
		if e.At, err = parseTime(at); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// TakenAddresses returns the addresses in use for kind "router", "backhaul" or
// "admin". Live rows map to the zero time; released routers map to released_at.
func (s *Store) TakenAddresses(kind string) (map[netip.Addr]time.Time, error) {
	var q string
	switch kind {
	case "router":
		q = `SELECT address, released_at FROM routers`
	case "backhaul":
		q = `SELECT backhaul_addr, NULL FROM hubs`
	case "admin":
		q = `SELECT address, NULL FROM admin_peers`
	default:
		return nil, fmt.Errorf("store: unknown address kind %q", kind)
	}
	rows, err := s.db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[netip.Addr]time.Time{}
	for rows.Next() {
		var a string
		var released sql.NullString
		if err := rows.Scan(&a, &released); err != nil {
			return nil, err
		}
		addr, err := parseAddr(a)
		if err != nil {
			return nil, err
		}
		var at time.Time
		if released.Valid {
			if at, err = parseTime(released.String); err != nil {
				return nil, err
			}
		}
		if prev, seen := out[addr]; seen && (prev.IsZero() || (!at.IsZero() && at.Before(prev))) {
			continue
		}
		out[addr] = at
	}
	return out, rows.Err()
}

// HubRouterCounts returns, per hub, how many unreleased routers list it.
func (s *Store) HubRouterCounts() (map[string]int, error) {
	rows, err := s.db.Query(`SELECT rh.hub_id, COUNT(*) FROM router_hubs rh
		JOIN routers r ON r.id = rh.router_id WHERE r.released_at IS NULL GROUP BY rh.hub_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}
