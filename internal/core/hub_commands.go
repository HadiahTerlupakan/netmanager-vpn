package core

import "fmt"

// hubCommand is the line an operator pastes on a hub VPS: arg is the join
// bundle for an install, or "upgrade" to move an installed hub to HubImage.
func (c *Core) hubCommand(arg string) string {
	return fmt.Sprintf("curl -fsSL %s | sudo NMVPN_IMAGE=%s sh -s -- %s", c.cfg.InstallURL, c.cfg.HubImage, arg)
}

// UpgradeCommand returns the command that moves an installed hub to the image
// this core was released with, keeping its keys and peers.
func (c *Core) UpgradeCommand(id string) (string, error) {
	if _, err := c.st.GetHub(id); err != nil {
		return "", err
	}
	return c.hubCommand("upgrade"), nil
}
