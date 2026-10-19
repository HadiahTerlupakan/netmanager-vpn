package core

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"
	"unicode/utf8"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/ipam"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const maxAdminLabel = 64

// AdminPeer is an operator device as shown to callers. It has no private key
// field on purpose: the key leaves only through AdminConfig.
type AdminPeer struct {
	ID        string
	Label     string
	Address   netip.Addr
	PublicKey string
	CreatedAt time.Time
}

func adminView(p store.AdminPeer) AdminPeer {
	return AdminPeer{ID: p.ID, Label: p.Label, Address: p.Address, PublicKey: p.PublicKey, CreatedAt: p.CreatedAt}
}

// CreateAdminPeer registers a device that can reach routers through wg-core.
// A freed address is reused at once, unlike a router's: every device gets a new
// key and wg-core authenticates by key, so only a router's nas.nasname in
// netmanager makes a quick reuse unsafe.
func (c *Core) CreateAdminPeer(label string) (AdminPeer, error) {
	if n := utf8.RuneCountInString(label); strings.TrimSpace(label) == "" || n > maxAdminLabel {
		return AdminPeer{}, fmt.Errorf("%w: label must be 1-%d characters", ErrValidation, maxAdminLabel)
	}
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return AdminPeer{}, err
	}
	sealed, err := c.box.Seal(key.String())
	if err != nil {
		return AdminPeer{}, err
	}
	row, err := c.storeNewAdmin(label, key.PublicKey().String(), sealed)
	if err != nil {
		return AdminPeer{}, err
	}
	if err := c.applyCore(); err != nil {
		return AdminPeer{}, c.rollbackAdmin(row.ID, err)
	}
	return adminView(row), nil
}

// storeNewAdmin retries once on a conflict: two creations can pick the same
// free address between TakenAddresses and the insert.
func (c *Core) storeNewAdmin(label, public, sealed string) (store.AdminPeer, error) {
	for attempt := 0; ; attempt++ {
		taken, err := c.st.TakenAddresses("admin")
		if err != nil {
			return store.AdminPeer{}, err
		}
		if c.afterAdminTaken != nil {
			c.afterAdminTaken()
		}
		addr, err := ipam.Allocate(ipam.AdminPool, ipam.AdminFirst, ipam.AdminLast, taken, c.cfg.Now())
		if err != nil {
			return store.AdminPeer{}, fmt.Errorf("core: allocate admin address: %w", err)
		}
		row, err := c.st.CreateAdminPeer(store.AdminPeer{Label: label, Address: addr, PublicKey: public, PrivateKey: sealed})
		if errors.Is(err, store.ErrConflict) && attempt == 0 {
			continue
		}
		return row, err
	}
}

// rollbackAdmin removes a peer whose wg-core registration failed, so no
// invisible peer or leaked admin address is left behind. It re-applies so a
// device that took the half-applied peer drops it.
func (c *Core) rollbackAdmin(id string, cause error) error {
	if err := c.st.DeleteAdminPeer(id); err != nil {
		return errors.Join(cause, fmt.Errorf("core: roll back admin peer: %w", err))
	}
	if err := c.applyCore(); err != nil {
		return errors.Join(cause, err)
	}
	return cause
}

// AdminConfig renders the wg-quick file for a device. AllowedIPs lists the
// backhaul and router pools only, so the device's other traffic stays off the VPN.
func (c *Core) AdminConfig(id string) (string, error) {
	peers, err := c.st.ListAdminPeers()
	if err != nil {
		return "", err
	}
	for _, p := range peers {
		if p.ID == id {
			return c.renderAdminConfig(p)
		}
	}
	return "", fmt.Errorf("core: admin peer %s: %w", id, store.ErrNotFound)
}

func (c *Core) renderAdminConfig(p store.AdminPeer) (string, error) {
	priv, err := c.box.Open(p.PrivateKey)
	if err != nil {
		return "", err
	}
	corePriv, err := c.corePrivateKey()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = %s\nAddress = %s\n\n"+
		"[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s, %s\nPersistentKeepalive = 25\n",
		priv, host32(p.Address), corePriv.PublicKey(), c.cfg.CoreEndpoint,
		ipam.BackhaulPool, ipam.RouterPool), nil
}

// DeleteAdminPeer removes a device and drops its wg-core peer. It applies even
// when the row is already gone: a delete whose apply failed leaves the device
// live on wg-core, and only a retry that still reaches applyCore revokes it.
func (c *Core) DeleteAdminPeer(id string) error {
	delErr := c.st.DeleteAdminPeer(id)
	if delErr != nil && !errors.Is(delErr, store.ErrNotFound) {
		return fmt.Errorf("core: delete admin peer: %w", delErr)
	}
	if err := c.applyCore(); err != nil {
		return err
	}
	if delErr != nil {
		return fmt.Errorf("core: delete admin peer: %w", delErr)
	}
	return nil
}

// ListAdminPeers returns every admin device, oldest first.
func (c *Core) ListAdminPeers() ([]AdminPeer, error) {
	rows, err := c.st.ListAdminPeers()
	if err != nil {
		return nil, err
	}
	out := make([]AdminPeer, 0, len(rows))
	for _, p := range rows {
		out = append(out, adminView(p))
	}
	return out, nil
}
