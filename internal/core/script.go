package core

import (
	"fmt"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
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
	return c.routerInputFor(rt, routerProtocol(rt))
}

// routerInputFor builds the script input for protocol, which need not be the
// router's current one: the operator pastes the next protocol's script first.
func (c *Core) routerInputFor(rt store.Router, protocol string) (routeros.Input, error) {
	in := routeros.Input{Label: rt.Label, Address: rt.Address, Protocol: protocol}
	var err error
	if protocol == routeros.ProtocolL2TP {
		in.PPPUser = rt.PPPUser
		in.PPPPassword, err = c.openIfSet(rt.PPPPassword)
	} else {
		in.PrivateKey, err = c.box.Open(rt.PrivateKey)
	}
	if err != nil {
		return routeros.Input{}, err
	}
	hubs, err := c.routerHubs(rt.ID)
	if err != nil {
		return routeros.Input{}, err
	}
	for _, h := range hubs {
		s, err := c.server(h, protocol)
		if err != nil {
			return routeros.Input{}, err
		}
		in.Servers = append(in.Servers, s)
	}
	return in, nil
}

// openIfSet leaves an absent secret empty, for Validate to report.
func (c *Core) openIfSet(sealed string) (string, error) {
	if sealed == "" {
		return "", nil
	}
	return c.box.Open(sealed)
}
