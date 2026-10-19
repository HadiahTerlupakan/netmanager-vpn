package store

import "database/sql"

// SetRouterActiveHub records the hub carrying a live router; an empty hubID
// records that none does.
func (s *Store) SetRouterActiveHub(routerID, hubID string) error {
	hub := sql.NullString{String: hubID, Valid: hubID != ""}
	return affected(s.db.Exec(`UPDATE routers SET active_hub_id = ? WHERE id = ? AND released_at IS NULL`,
		hub, routerID))
}

// ClearRouterActiveHub forgets the active hub only while it is still hubID, so
// a clear racing a newer move cannot erase that move.
func (s *Store) ClearRouterActiveHub(routerID, hubID string) error {
	_, err := s.db.Exec(`UPDATE routers SET active_hub_id = NULL WHERE id = ? AND active_hub_id = ?`,
		routerID, hubID)
	return err
}

// ActiveHubs maps each live router to its recorded active hub. A hub no longer
// in the router's list is left out: it cannot be carrying the router.
func (s *Store) ActiveHubs() (map[string]string, error) {
	rows, err := s.db.Query(`SELECT r.id, r.active_hub_id FROM routers r
		JOIN router_hubs rh ON rh.router_id = r.id AND rh.hub_id = r.active_hub_id
		WHERE r.released_at IS NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, hub string
		if err := rows.Scan(&id, &hub); err != nil {
			return nil, err
		}
		out[id] = hub
	}
	return out, rows.Err()
}
