package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	// A handshake older than this means the router is not using that hub; it
	// matches the online window the hub statuses use.
	freshWindow = onlineWindow
	// The router switches hubs on its own and may bounce between two that both
	// look healthy; the core keeps the current hub unless another is clearly
	// ahead, so wg-core is not rebuilt every cycle for a coin flip.
	stickyMargin = 30 * time.Second
	// Hub clocks drift; a little skew is tolerated, but a stamp further ahead
	// would otherwise win as "newest" and hold a router on a dead hub.
	maxFutureSkew = 5 * time.Second
)

func usable(at, now time.Time) bool {
	d := now.Sub(at)
	return d >= -maxFutureSkew && d < freshWindow
}

// ChooseActive picks the hub carrying a router from the handshakes each hub
// saw for it. It returns nil when no handshake is fresh.
func ChooseActive(handshakes map[string]time.Time, current *string, now time.Time) *string {
	var best string
	var bestAt time.Time
	found := false
	for hub, at := range handshakes {
		if !usable(at, now) {
			continue
		}
		// Map order is random; the smallest ID on a tie keeps the result stable.
		if !found || at.After(bestAt) || (at.Equal(bestAt) && hub < best) {
			best, bestAt, found = hub, at, true
		}
	}
	if !found {
		return nil
	}
	if current != nil {
		if at, ok := handshakes[*current]; ok && usable(at, now) && bestAt.Sub(at) <= stickyMargin {
			return current
		}
	}
	return &best
}

// RunActiveLoop re-evaluates every router's hub each interval until ctx ends.
func (c *Core) RunActiveLoop(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.tick(ctx); err != nil {
				slog.Error("active hub pass failed", "err", err)
				continue
			}
			c.markOK()
		}
	}
}

type hubMove struct {
	routerID string
	from, to string
	prevAt   time.Time
	hadPrev  bool
}

// tick runs one pass. The status refresh comes first so a hub that
// handshook just before its join expired is persisted online before any
// applyCore can drop it. Each hub's Peers call is bounded by the HubClient's
// own timeout (5 s for the HTTP client), so one slow hub delays a pass by at
// most that.
func (c *Core) tick(ctx context.Context) error {
	if err := c.RefreshHubStatuses(); err != nil {
		return err
	}
	routers, err := c.st.ListRouters()
	if err != nil {
		return err
	}
	seen, err := c.collectHandshakes(ctx, routers)
	if err != nil {
		return err
	}
	moves, err := c.commitChoices(routers, seen)
	if err != nil || len(moves) == 0 {
		return err
	}
	if err := c.applyCore(); err != nil {
		c.revert(moves)
		return err
	}
	return c.recordMoves(moves)
}

// collectHandshakes asks every online hub for its peers, holding no lock: a
// slow hub must not stall mutations. A hub whose list cannot be read
// contributes the stamps it last reported, so its routers age out through
// freshWindow instead of all dropping on one failed call.
func (c *Core) collectHandshakes(ctx context.Context, routers []store.Router) (map[string]map[string]time.Time, error) {
	hubs, err := c.st.ListHubs()
	if err != nil {
		return nil, err
	}
	byKey := make(map[string]string, len(routers))
	for _, r := range routers {
		byKey[r.PublicKey] = r.ID
	}
	last := make(map[string]map[string]time.Time, len(hubs))
	out := map[string]map[string]time.Time{}
	for _, h := range hubs {
		if h.Status != store.HubStatusOnline {
			continue
		}
		seen, err := c.hubHandshakes(ctx, h, byKey)
		if err != nil {
			slog.Warn("hub peers unreadable, reusing last report", "hub", h.ID, "err", err)
			seen = c.lastSeen[h.ID]
		}
		last[h.ID] = seen
		for rid, at := range seen {
			if out[rid] == nil {
				out[rid] = map[string]time.Time{}
			}
			out[rid][h.ID] = at
		}
	}
	c.lastSeen = last
	return out, nil
}

// hubHandshakes maps router ID to the handshake one hub reports for it.
func (c *Core) hubHandshakes(ctx context.Context, h store.Hub, byKey map[string]string) (map[string]time.Time, error) {
	peers, err := c.hubs.Peers(ctx, h)
	if err != nil {
		return nil, err
	}
	seen := map[string]time.Time{}
	for _, p := range peers {
		if rid, ok := byKey[p.PublicKey]; ok && p.LastHandshakeAt != nil {
			seen[rid] = *p.LastHandshakeAt
		}
	}
	return seen, nil
}

// listedHandshakes keeps, per router, only the handshakes from hubs in its own
// list: a hub outside it never carries the router, whatever its peers report.
func (c *Core) listedHandshakes(routers []store.Router, seen map[string]map[string]time.Time) (map[string]map[string]time.Time, error) {
	out := make(map[string]map[string]time.Time, len(routers))
	for _, r := range routers {
		rhs, err := c.st.ListRouterHubs(r.ID)
		if err != nil {
			return nil, err
		}
		out[r.ID] = map[string]time.Time{}
		for _, rh := range rhs {
			if at, ok := seen[r.ID][rh.HubID]; ok {
				out[r.ID][rh.HubID] = at
			}
		}
	}
	return out, nil
}

// commitChoices stores each router's chosen hub and returns the ones that
// changed.
func (c *Core) commitChoices(routers []store.Router, seen map[string]map[string]time.Time) ([]hubMove, error) {
	listed, err := c.listedHandshakes(routers, seen)
	if err != nil {
		return nil, err
	}
	now := c.cfg.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	live := make(map[string]bool, len(routers))
	for _, r := range routers {
		live[r.ID] = true
	}
	for id := range c.active {
		if !live[id] {
			delete(c.active, id)
			delete(c.handshakes, id)
		}
	}
	var moves []hubMove
	for _, r := range routers {
		var cur *string
		prev, hadPrev := c.active[r.ID]
		if hadPrev {
			cur = &prev
		}
		next := ChooseActive(listed[r.ID], cur, now)
		m := hubMove{routerID: r.ID, from: prev, prevAt: c.handshakes[r.ID], hadPrev: hadPrev}
		if next == nil {
			delete(c.active, r.ID)
			delete(c.handshakes, r.ID)
		} else {
			m.to = *next
			c.active[r.ID] = *next
			c.handshakes[r.ID] = listed[r.ID][*next]
		}
		if m.from != m.to {
			moves = append(moves, m)
		}
	}
	return moves, nil
}

// revert undoes a failed apply so the next pass sees the same change again
// instead of believing the kernel already has it. A router whose entry no
// longer matches what this pass set was changed meanwhile (forgetActive,
// DeleteRouter) and is left alone.
func (c *Core) revert(moves []hubMove) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, m := range moves {
		if now, ok := c.active[m.routerID]; (m.to == "" && ok) || (m.to != "" && now != m.to) {
			continue
		}
		if m.hadPrev {
			c.active[m.routerID] = m.from
			c.handshakes[m.routerID] = m.prevAt
		} else {
			delete(c.active, m.routerID)
			delete(c.handshakes, m.routerID)
		}
	}
}

// recordMoves runs only after applyCore succeeded, so the log never claims a
// move the kernel did not get.
func (c *Core) recordMoves(moves []hubMove) error {
	now := c.cfg.Now()
	var errs []error
	for _, m := range moves {
		if err := c.st.SetRouterActiveHub(m.routerID, m.to); err != nil && !errors.Is(err, store.ErrNotFound) {
			errs = append(errs, fmt.Errorf("core: persist active hub of %s: %w", m.routerID, err))
		}
		if err := c.st.AddRouterEvent(m.routerID, m.from, m.to, now); err != nil {
			errs = append(errs, fmt.Errorf("core: record move of %s: %w", m.routerID, err))
		}
	}
	return errors.Join(errs...)
}
