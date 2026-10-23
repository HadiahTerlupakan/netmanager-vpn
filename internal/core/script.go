package core

import (
	"fmt"
	"sort"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
)

// RouterScript renders the RouterOS script for a router. part is "full" for
// the whole setup, "scheduler" for the switch script and its scheduler, or
// "switch" for the switch script's source alone, which a router takes over
// /system/script set source= without re-pasting the scheduler.
func (c *Core) RouterScript(id, part string) (string, error) {
	if part != "full" && part != "scheduler" && part != "switch" {
		return "", fmt.Errorf("%w: part must be full, scheduler or switch", ErrValidation)
	}
	in, err := c.routerInput(id)
	if err != nil {
		return "", err
	}
	if err := in.Validate(); err != nil {
		return "", fmt.Errorf("%w: %v", ErrValidation, err)
	}
	switch part {
	case "scheduler":
		return routeros.RenderScheduler(in), nil
	case "switch":
		return routeros.SwitchSource(in), nil
	}
	return routeros.RenderFull(in), nil
}

func (c *Core) routerInput(id string) (routeros.Input, error) {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return routeros.Input{}, err
	}
	priv, err := c.box.Open(rt.PrivateKey)
	if err != nil {
		return routeros.Input{}, err
	}
	links, err := c.st.ListRouterHubs(id)
	if err != nil {
		return routeros.Input{}, err
	}
	sort.SliceStable(links, func(i, j int) bool { return links[i].Priority < links[j].Priority })
	in := routeros.Input{Label: rt.Label, Address: rt.Address, PrivateKey: priv}
	for _, l := range links {
		h, err := c.st.GetHub(l.HubID)
		if err != nil {
			return routeros.Input{}, err
		}
		in.Servers = append(in.Servers, routeros.Server{Host: h.PublicHost, Port: h.ListenPort, PublicKey: h.PublicKey})
	}
	return in, nil
}
