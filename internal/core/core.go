// Package core runs the control plane: the hub registry, routers, and the
// wg-core interface every hub tunnels into.
package core

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

const (
	ifaceCore   = "wg-core"
	coreAddress = "10.99.0.1/24"
	corePort    = 51822
	coreMTU     = 1380
	// healthWindow is how stale the last good reconcile may be; the active pass
	// runs every 10 s, so a minute means several missed passes.
	healthWindow = 60 * time.Second
)

// ErrValidation marks input the caller can fix.
var ErrValidation = errors.New("core: invalid input")

// Config is the core's deployment-specific settings.
type Config struct {
	// CoreEndpoint is wg-core's public host:port, which hubs dial.
	CoreEndpoint string
	InstallURL   string
	// HubImage is the exact, pinned image a new hub pulls; a moving tag would
	// let hubs drift from the core.
	HubImage string
	Now      func() time.Time
}

// Core owns the registry and the wg-core interface.
type Core struct {
	dev  wgdevice.Device
	st   *store.Store
	box  *secret.Box
	hubs HubClient
	cfg  Config

	// mu guards active; applyMu serializes writes to the device so two
	// mutations cannot interleave a stale config over a fresh one.
	mu     sync.Mutex
	active map[string]string // router ID -> hub ID currently carrying it
	// handshakes holds the newest router handshake seen on its active hub.
	handshakes map[string]time.Time
	// lastSeen keeps each hub's last readable report (hub ID -> router ID ->
	// handshake). Only tick touches it, from the one active-loop goroutine.
	lastSeen map[string]map[string]time.Time
	applyMu  sync.Mutex
	// regMu serializes registry rewrites (status refresh, join reissue) so a
	// stale snapshot cannot overwrite a freshly reissued hub.
	regMu sync.Mutex
	// afterAdminTaken lets a test slip a competing insert between the address
	// lookup and the insert, which cannot be timed reliably with goroutines.
	afterAdminTaken func()
	// okAt is the unix-nano time of the last successful apply or active pass.
	okAt atomic.Int64
}

// New builds a Core. A nil cfg.Now means time.Now.
func New(dev wgdevice.Device, st *store.Store, box *secret.Box, hubs HubClient, cfg Config) *Core {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Core{dev: dev, st: st, box: box, hubs: hubs, cfg: cfg, active: map[string]string{}, handshakes: map[string]time.Time{},
		lastSeen: map[string]map[string]time.Time{}}
}

// Init makes sure wg-core has a key and applies its configuration. The active
// hubs recorded before a restart are seeded first, so the first apply keeps
// every router routed instead of waiting for the next pass. Handshakes stay
// empty: they are only known once a hub has been asked.
func (c *Core) Init() error {
	if _, err := c.corePrivateKey(); err != nil {
		return err
	}
	active, err := c.st.ActiveHubs()
	if err != nil {
		return err
	}
	c.mu.Lock()
	for routerID, hubID := range active {
		c.active[routerID] = hubID
	}
	c.mu.Unlock()
	return c.applyCore()
}

func (c *Core) corePrivateKey() (wgtypes.Key, error) {
	sealed, err := c.st.ServerKey(ifaceCore)
	if errors.Is(err, store.ErrNotFound) {
		return c.createCoreKey()
	}
	if err != nil {
		return wgtypes.Key{}, err
	}
	plain, err := c.box.Open(sealed)
	if err != nil {
		return wgtypes.Key{}, err
	}
	return wgtypes.ParseKey(plain)
}

func (c *Core) createCoreKey() (wgtypes.Key, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return wgtypes.Key{}, err
	}
	sealed, err := c.box.Seal(key.String())
	if err != nil {
		return wgtypes.Key{}, err
	}
	return key, c.st.SetServerKey(ifaceCore, sealed)
}

// applyCore rebuilds wg-core from the store and the active map. Every
// mutation ends here so the interface never drifts from the registry.
func (c *Core) applyCore() error {
	c.applyMu.Lock()
	defer c.applyMu.Unlock()
	key, err := c.corePrivateKey()
	if err != nil {
		return err
	}
	hubs, err := c.st.ListHubs()
	if err != nil {
		return err
	}
	admins, err := c.st.ListAdminPeers()
	if err != nil {
		return err
	}
	routed, err := c.routedAddrs()
	if err != nil {
		return err
	}
	cfg := wgdevice.Config{InterfaceName: ifaceCore, PrivateKey: key.String(),
		Address: coreAddress, ListenPort: corePort, MTU: coreMTU}
	for _, h := range hubs {
		if h.Status == store.HubStatusExpired ||
			(h.Status == store.HubStatusPendingInstall && c.cfg.Now().After(h.JoinExpiresAt)) {
			continue
		}
		ips := append([]string{host32(h.BackhaulAddr)}, routed[h.ID]...)
		cfg.Peers = append(cfg.Peers, wgdevice.PeerConfig{PublicKey: h.PublicKey, AllowedIPs: ips})
	}
	for _, a := range admins {
		cfg.Peers = append(cfg.Peers, wgdevice.PeerConfig{PublicKey: a.PublicKey, AllowedIPs: []string{host32(a.Address)}})
	}
	if err := c.dev.Apply(cfg); err != nil {
		return fmt.Errorf("core: apply %s: %w", ifaceCore, err)
	}
	c.markOK()
	return nil
}

func (c *Core) markOK() { c.okAt.Store(c.cfg.Now().UnixNano()) }

// Healthy reports whether wg-core was applied or an active pass finished
// within healthWindow of now.
func (c *Core) Healthy(now time.Time) bool {
	at := c.okAt.Load()
	return at != 0 && now.Sub(time.Unix(0, at)) < healthWindow
}

// routedAddrs lists, per hub, the /32 of every router currently active on it.
func (c *Core) routedAddrs() (map[string][]string, error) {
	c.mu.Lock()
	snapshot := make(map[string]string, len(c.active))
	for r, h := range c.active {
		snapshot[r] = h
	}
	c.mu.Unlock()
	if len(snapshot) == 0 {
		return nil, nil
	}
	routers, err := c.st.ListRouters()
	if err != nil {
		return nil, err
	}
	out := map[string][]string{}
	for _, r := range routers {
		if hubID, ok := snapshot[r.ID]; ok {
			out[hubID] = append(out[hubID], host32(r.Address))
		}
	}
	return out, nil
}

func host32(a netip.Addr) string { return netip.PrefixFrom(a, 32).String() }
