package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ipam"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	maxLabelLen     = 64
	pendingLifetime = 24 * time.Hour
	eventsShown     = 20
)

// RouterView is a router as shown to operators.
type RouterView struct {
	ID, Label, Ref, Address, Status string
	Hubs                            []RouterHub
	ActiveHubID                     *string
	LastHandshakeAt                 *time.Time
	Events                          []RouterEvent
}

// RouterHub is one entry of a router's ordered server list.
type RouterHub struct {
	HubID, Name string
	Priority    int
	SyncState   string
}

// RouterEvent is a change of the hub carrying a router.
type RouterEvent struct {
	FromHubID, ToHubID *string
	At                 time.Time
}

// CreateRouter registers one keypair and /32 on every listed hub, so the
// router can switch hubs without the core handing it new credentials. A hub
// that cannot be reached stays sync_state=pending for SyncPending.
func (c *Core) CreateRouter(ctx context.Context, label string, hubIDs []string) (RouterView, error) {
	if label == "" || len(label) > maxLabelLen {
		return RouterView{}, fmt.Errorf("%w: label must be 1-%d characters", ErrValidation, maxLabelLen)
	}
	hubs, err := c.validateHubIDs(hubIDs)
	if err != nil {
		return RouterView{}, err
	}
	rt, err := c.storeNewRouter(label)
	if err != nil {
		return RouterView{}, err
	}
	if err := c.st.SetRouterHubs(rt.ID, hubIDs); err != nil {
		return RouterView{}, errors.Join(err, c.st.DeleteRouter(rt.ID))
	}
	for _, h := range hubs {
		c.pushPeer(ctx, rt, h)
	}
	if err := c.applyCore(); err != nil {
		return RouterView{}, err
	}
	return c.GetRouter(rt.ID)
}

// storeNewRouter retries once on a conflict: two creations can pick the same
// free address between TakenAddresses and the insert.
func (c *Core) storeNewRouter(label string) (store.Router, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return store.Router{}, err
	}
	sealed, err := c.box.Seal(key.String())
	if err != nil {
		return store.Router{}, err
	}
	for attempt := 0; ; attempt++ {
		taken, err := c.st.TakenAddresses("router")
		if err != nil {
			return store.Router{}, err
		}
		addr, err := ipam.Allocate(ipam.RouterPool, ipam.RouterFirst, ipam.RouterLast, taken, c.cfg.Now())
		if err != nil {
			return store.Router{}, fmt.Errorf("core: allocate router address: %w", err)
		}
		rt, err := c.st.CreateRouter(store.Router{Label: label, Address: addr,
			PublicKey: key.PublicKey().String(), PrivateKey: sealed, Status: store.RouterStatusPending})
		if errors.Is(err, store.ErrConflict) && attempt == 0 {
			continue
		}
		return rt, err
	}
}

// validateHubIDs requires at least one hub, no repeats, and every hub online:
// a router cannot use a server that has never connected.
func (c *Core) validateHubIDs(ids []string) ([]store.Hub, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: at least one hub is required", ErrValidation)
	}
	seen := map[string]bool{}
	hubs := make([]store.Hub, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			return nil, fmt.Errorf("%w: hub %s listed twice", ErrValidation, id)
		}
		seen[id] = true
		h, err := c.st.GetHub(id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("%w: unknown hub %s", ErrValidation, id)
		}
		if err != nil {
			return nil, err
		}
		if h.Status != store.HubStatusOnline {
			return nil, fmt.Errorf("%w: hub %s is %s, not online", ErrValidation, h.Name, h.Status)
		}
		hubs = append(hubs, h)
	}
	return hubs, nil
}

// pushPeer registers the router on a hub and records the outcome. A failure is
// not returned: the row stays pending and SyncPending retries it.
func (c *Core) pushPeer(ctx context.Context, rt store.Router, h store.Hub) {
	if err := c.hubs.UpsertPeer(ctx, h, rt.PublicKey, rt.Address); err != nil {
		slog.Warn("router peer not registered, left pending", "router", rt.ID, "hub", h.ID, "err", err)
		return
	}
	if err := c.st.UpdateRouterHubSyncState(rt.ID, h.ID, store.SyncStateSynced); err != nil {
		slog.Warn("router sync state not recorded", "router", rt.ID, "hub", h.ID, "err", err)
	}
}

// SetRouterHubs replaces the router's ordered hub list.
func (c *Core) SetRouterHubs(ctx context.Context, id string, hubIDs []string) error {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return err
	}
	hubs, err := c.validateHubIDs(hubIDs)
	if err != nil {
		return err
	}
	old, err := c.st.ListRouterHubs(id)
	if err != nil {
		return err
	}
	if err := c.st.SetRouterHubs(id, hubIDs); err != nil {
		return err
	}
	kept := map[string]bool{}
	for _, h := range hubs {
		kept[h.ID] = true
	}
	had := map[string]bool{}
	for _, o := range old {
		had[o.HubID] = true
		if !kept[o.HubID] {
			c.dropPeer(ctx, rt, o.HubID)
		}
	}
	for _, h := range hubs {
		if !had[h.ID] {
			c.pushPeer(ctx, rt, h)
		}
	}
	return c.applyCore()
}

// dropPeer removes the router from a hub. A failure is only logged: the prune
// in SyncPending removes whatever is left.
func (c *Core) dropPeer(ctx context.Context, rt store.Router, hubID string) {
	h, err := c.st.GetHub(hubID)
	if err != nil {
		slog.Warn("hub lookup for peer removal failed", "hub", hubID, "err", err)
		return
	}
	if err := c.hubs.DeletePeer(ctx, h, rt.PublicKey); err != nil {
		slog.Warn("router peer not removed from hub", "router", rt.ID, "hub", hubID, "err", err)
	}
}

// ClaimRouter marks a pending router as claimed by its device.
func (c *Core) ClaimRouter(id, ref string) error {
	if ref == "" {
		return fmt.Errorf("%w: ref is empty", ErrValidation)
	}
	if err := c.st.ClaimRouter(id, ref); err != nil {
		return fmt.Errorf("core: claim router: %w", err)
	}
	return nil
}

// DeleteRouter soft-deletes the router, then removes its peer from every hub.
func (c *Core) DeleteRouter(ctx context.Context, id string) error {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return err
	}
	links, err := c.st.ListRouterHubs(id)
	if err != nil {
		return err
	}
	if err := c.st.DeleteRouter(id); err != nil {
		return err
	}
	for _, l := range links {
		c.dropPeer(ctx, rt, l.HubID)
	}
	c.mu.Lock()
	delete(c.active, id)
	delete(c.handshakes, id)
	c.mu.Unlock()
	return c.applyCore()
}

// ExpirePending deletes routers nobody claimed within 24 hours.
func (c *Core) ExpirePending(ctx context.Context, now time.Time) (int, error) {
	routers, err := c.st.ListRouters()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range routers {
		if r.Status != store.RouterStatusPending || now.Sub(r.CreatedAt) <= pendingLifetime {
			continue
		}
		if err := c.DeleteRouter(ctx, r.ID); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}
