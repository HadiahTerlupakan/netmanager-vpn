package core

import (
	"fmt"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	ikePort    = 500
	ikeNATPort = 4500
)

// hubCommand is the line an operator pastes on a hub VPS: arg is the join
// bundle for an install, or "upgrade" to move an installed hub to HubImage.
// Many VPS images log in as root and ship no sudo: `$(command -v sudo)` then
// expands to nothing, and env sets the variable either way.
func (c *Core) hubCommand(h store.Hub, arg string) string {
	return fmt.Sprintf("curl -fsSL %s | $(command -v sudo) env NMVPN_IMAGE=%s NMVPN_PORTS=\"%s\" sh -s -- %s",
		c.cfg.InstallURL, c.cfg.HubImage, hubPorts(h), arg)
}

// hubPorts lists what the hub's host must leave free and open: WireGuard on
// the hub's own port, and IKE with NAT-T for L2TP/IPsec.
func hubPorts(h store.Hub) string {
	return fmt.Sprintf("%d/udp %d/udp %d/udp", h.ListenPort, ikePort, ikeNATPort)
}

// UpgradeCommand returns the command that moves an installed hub to the image
// this core was released with, keeping its keys and peers.
func (c *Core) UpgradeCommand(id string) (string, error) {
	h, err := c.st.GetHub(id)
	if err != nil {
		return "", err
	}
	return c.hubCommand(h, "upgrade"), nil
}
