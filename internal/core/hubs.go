package core

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/netip"
	"regexp"
	"time"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ipam"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	defaultHubPort = 51821
	joinValidity   = time.Hour
	onlineWindow   = 180 * time.Second
	apiTokenBytes  = 32
)

var hostnameRE = regexp.MustCompile(`^([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

// HubView is a hub as shown to operators.
type HubView struct {
	ID          string
	Name        string
	PublicHost  string
	ListenPort  int
	Status      string
	RouterCount int
	LastSeenAt  *time.Time
}

// CreateHub registers a hub and returns the command the operator runs on it.
func (c *Core) CreateHub(name, publicHost string, port int) (store.Hub, string, error) {
	if port == 0 {
		port = defaultHubPort
	}
	if err := validateHub(name, publicHost, port); err != nil {
		return store.Hub{}, "", err
	}
	taken, err := c.st.TakenAddresses("backhaul")
	if err != nil {
		return store.Hub{}, "", err
	}
	addr, err := ipam.Allocate(ipam.BackhaulPool, ipam.BackhaulFirst, ipam.BackhaulLast, taken, c.cfg.Now())
	if err != nil {
		return store.Hub{}, "", fmt.Errorf("core: allocate backhaul: %w", err)
	}
	cred, err := c.newHubCredentials()
	if err != nil {
		return store.Hub{}, "", err
	}
	hub, err := c.st.CreateHub(store.Hub{
		Name: name, PublicHost: publicHost, ListenPort: port, BackhaulAddr: addr,
		PublicKey: cred.public, PrivateKey: cred.sealedPrivate, APIToken: cred.sealedToken,
		Status: store.HubStatusPendingInstall, JoinExpiresAt: c.cfg.Now().Add(joinValidity),
	})
	if err != nil {
		return store.Hub{}, "", err
	}
	cmd, err := c.finishJoin(hub, cred)
	return hub, cmd, err
}

// ReissueJoin rotates a hub's keys for a fresh install. A hub that has
// connected is refused: the new key would cut it off until reinstalled.
func (c *Core) ReissueJoin(id string) (string, error) {
	hub, err := c.st.GetHub(id)
	if err != nil {
		return "", err
	}
	if hub.Status != store.HubStatusPendingInstall && hub.Status != store.HubStatusExpired {
		return "", fmt.Errorf("%w: hub is %s, its key cannot be rotated", ErrValidation, hub.Status)
	}
	cred, err := c.newHubCredentials()
	if err != nil {
		return "", err
	}
	expiry := c.cfg.Now().Add(joinValidity)
	if err := c.st.UpdateHubKeys(id, cred.public, cred.sealedPrivate, cred.sealedToken, expiry); err != nil {
		return "", err
	}
	if err := c.st.UpdateHubStatus(id, store.HubStatusPendingInstall, nil); err != nil {
		return "", err
	}
	hub.JoinExpiresAt = expiry
	return c.finishJoin(hub, cred)
}

// DeleteHub removes a hub no router lists.
func (c *Core) DeleteHub(id string) error {
	if err := c.st.DeleteHub(id); err != nil {
		return fmt.Errorf("core: delete hub: %w", err)
	}
	return c.applyCore()
}

// ListHubs returns every hub with the number of routers listing it.
func (c *Core) ListHubs() ([]HubView, error) {
	hubs, err := c.st.ListHubs()
	if err != nil {
		return nil, err
	}
	counts, err := c.routerCounts()
	if err != nil {
		return nil, err
	}
	out := make([]HubView, 0, len(hubs))
	for _, h := range hubs {
		out = append(out, HubView{ID: h.ID, Name: h.Name, PublicHost: h.PublicHost,
			ListenPort: h.ListenPort, Status: h.Status, RouterCount: counts[h.ID], LastSeenAt: h.LastSeenAt})
	}
	return out, nil
}

func (c *Core) routerCounts() (map[string]int, error) {
	routers, err := c.st.ListRouters()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, r := range routers {
		links, err := c.st.ListRouterHubs(r.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range links {
			counts[l.HubID]++
		}
	}
	return counts, nil
}

// RefreshHubStatuses recomputes every hub's status from wg-core handshakes.
func (c *Core) RefreshHubStatuses() error {
	live, err := c.dev.Status(ifaceCore)
	if err != nil {
		return err
	}
	handshakes := make(map[string]*time.Time, len(live))
	for _, p := range live {
		handshakes[p.PublicKey] = p.LastHandshakeAt
	}
	hubs, err := c.st.ListHubs()
	if err != nil {
		return err
	}
	now := c.cfg.Now()
	expired := false
	for _, h := range hubs {
		hs := handshakes[h.PublicKey]
		status := hubStatus(h.Status, h.JoinExpiresAt, hs, now)
		if status == h.Status && !newerThan(hs, h.LastSeenAt) {
			continue
		}
		if err := c.st.UpdateHubStatus(h.ID, status, hs); err != nil {
			return err
		}
		expired = expired || (status == store.HubStatusExpired && h.Status != status)
	}
	if expired {
		return c.applyCore()
	}
	return nil
}

func newerThan(hs, seen *time.Time) bool {
	return hs != nil && (seen == nil || hs.After(*seen))
}

// hubStatus derives a hub's state. A hub that has handshaked once keeps
// online/offline for good; only one that never connected can expire.
func hubStatus(stored string, joinExpiresAt time.Time, handshake *time.Time, now time.Time) string {
	switch {
	case handshake != nil && now.Sub(*handshake) < onlineWindow:
		return store.HubStatusOnline
	case handshake != nil, stored == store.HubStatusOnline, stored == store.HubStatusOffline:
		return store.HubStatusOffline
	case stored == store.HubStatusExpired, now.After(joinExpiresAt):
		return store.HubStatusExpired
	}
	return store.HubStatusPendingInstall
}

type hubCredentials struct {
	private, public, token, sealedPrivate, sealedToken string
}

func (c *Core) newHubCredentials() (hubCredentials, error) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return hubCredentials{}, err
	}
	raw := make([]byte, apiTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return hubCredentials{}, err
	}
	cred := hubCredentials{private: key.String(), public: key.PublicKey().String(),
		token: base64.RawURLEncoding.EncodeToString(raw)}
	if cred.sealedPrivate, err = c.box.Seal(cred.private); err != nil {
		return hubCredentials{}, err
	}
	cred.sealedToken, err = c.box.Seal(cred.token)
	return cred, err
}

func (c *Core) finishJoin(hub store.Hub, cred hubCredentials) (string, error) {
	if err := c.applyCore(); err != nil {
		return "", err
	}
	corePriv, err := c.corePrivateKey()
	if err != nil {
		return "", err
	}
	b := joinbundle.Bundle{CoreEndpoint: c.cfg.CoreEndpoint, CorePublicKey: corePriv.PublicKey().String(),
		BackhaulAddr: hub.BackhaulAddr.String(), PrivateKey: cred.private, APIToken: cred.token,
		ExpiresAt: hub.JoinExpiresAt}
	return fmt.Sprintf("curl -fsSL %s | sudo sh -s -- %s", c.cfg.InstallURL, b.Encode()), nil
}

func validateHub(name, host string, port int) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: name is empty", ErrValidation)
	case port < 1 || port > 65535:
		return fmt.Errorf("%w: port %d out of range", ErrValidation, port)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if len(host) > 253 || !hostnameRE.MatchString(host) {
		return fmt.Errorf("%w: public host must be a hostname or IP without scheme or port", ErrValidation)
	}
	return nil
}
