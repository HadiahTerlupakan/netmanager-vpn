package core

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ipam"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	maxLabelLen     = 64
	pendingLifetime = 24 * time.Hour
	eventsShown     = 20
)

// RouterView is a router as shown to operators.
type RouterView struct {
	ID              string        `json:"id"`
	Label           string        `json:"label"`
	Ref             string        `json:"ref"`
	Address         string        `json:"address"`
	Status          string        `json:"status"`
	Protocol        string        `json:"protocol"`
	Hubs            []RouterHub   `json:"hubs"`
	ActiveHubID     *string       `json:"activeHubId"`
	LastHandshakeAt *time.Time    `json:"lastHandshakeAt"`
	Events          []RouterEvent `json:"events"`
}

// RouterHub is one entry of a router's ordered server list.
type RouterHub struct {
	HubID     string `json:"hubId"`
	Name      string `json:"name"`
	Priority  int    `json:"priority"`
	SyncState string `json:"syncState"`
}

// RouterEvent is a change of the hub carrying a router.
type RouterEvent struct {
	FromHubID *string   `json:"fromHubId"`
	ToHubID   *string   `json:"toHubId"`
	At        time.Time `json:"at"`
}

// CreateRouter registers one keypair and /32 on every listed hub, so the
// router can switch hubs without the core handing it new credentials. A hub
// that cannot be reached stays sync_state=pending for SyncPending. An empty
// protocol means WireGuard.
func (c *Core) CreateRouter(ctx context.Context, label string, hubIDs []string, protocol string) (RouterView, error) {
	if label == "" || len(label) > maxLabelLen {
		return RouterView{}, fmt.Errorf("%w: label must be 1-%d characters", ErrValidation, maxLabelLen)
	}
	protocol, err := normalizeProtocol(protocol)
	if err != nil {
		return RouterView{}, err
	}
	hubs, err := c.validateHubIDs(hubIDs, protocol)
	if err != nil {
		return RouterView{}, err
	}
	rt, err := c.storeNewRouter(label, protocol)
	if err != nil {
		return RouterView{}, err
	}
	if protocol == routeros.ProtocolL2TP {
		withLogin, err := c.ensurePPP(rt)
		if err != nil {
			return RouterView{}, errors.Join(err, c.st.DeleteRouter(rt.ID))
		}
		rt = withLogin
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
func (c *Core) storeNewRouter(label, protocol string) (store.Router, error) {
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
			PublicKey: key.PublicKey().String(), PrivateKey: sealed, Status: store.RouterStatusPending, Protocol: protocol})
		if errors.Is(err, store.ErrConflict) && attempt == 0 {
			continue
		}
		return rt, err
	}
}

// validateHubIDs requires at least one hub, no repeats, and every hub online
// and serving the protocol: a router cannot use a server that has never
// connected.
func (c *Core) validateHubIDs(ids []string, protocol string) ([]store.Hub, error) {
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
		if err := requireSupport(h, protocol); err != nil {
			return nil, err
		}
		hubs = append(hubs, h)
	}
	return hubs, nil
}

// SetRouterHubs replaces the router's ordered hub list.
func (c *Core) SetRouterHubs(ctx context.Context, id string, hubIDs []string) error {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return err
	}
	hubs, err := c.validateHubIDs(hubIDs, routerProtocol(rt))
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
			c.forgetActive(id, o.HubID)
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

// forgetActive clears the router's live state when the hub carrying it is
// removed from its list, so wg-core stops routing it there.
func (c *Core) forgetActive(routerID, hubID string) {
	c.mu.Lock()
	if c.active[routerID] == hubID {
		delete(c.active, routerID)
		delete(c.handshakes, routerID)
	}
	c.mu.Unlock()
	if err := c.st.ClearRouterActiveHub(routerID, hubID); err != nil {
		slog.Warn("recorded active hub not cleared", "router", routerID, "hub", hubID, "err", err)
	}
}

// DeleteRouter soft-deletes the router, then removes its peer from every hub.
func (c *Core) DeleteRouter(ctx context.Context, id string) error {
	return c.removeRouter(ctx, id, c.st.DeleteRouter)
}

func (c *Core) removeRouter(ctx context.Context, id string, del func(string) error) error {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return err
	}
	links, err := c.st.ListRouterHubs(id)
	if err != nil {
		return err
	}
	if err := del(id); err != nil {
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
	var errs []error
	for _, r := range routers {
		if r.Status != store.RouterStatusPending || now.Sub(r.CreatedAt) <= pendingLifetime {
			continue
		}
		err := c.removeRouter(ctx, r.ID, c.st.DeleteRouterIfPending)
		switch {
		case errors.Is(err, store.ErrNotFound):
		case err != nil:
			errs = append(errs, err)
		default:
			n++
		}
	}
	return n, errors.Join(errs...)
}
