package core

import (
	"log/slog"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// GetRouter returns the router with its server list and recent hub changes.
func (c *Core) GetRouter(id string) (RouterView, error) {
	rt, err := c.st.GetRouter(id)
	if err != nil {
		return RouterView{}, err
	}
	links, err := c.st.ListRouterHubs(id)
	if err != nil {
		return RouterView{}, err
	}
	events, err := c.st.ListRouterEvents(id, eventsShown)
	if err != nil {
		return RouterView{}, err
	}
	v := RouterView{ID: rt.ID, Label: rt.Label, Ref: rt.Ref, Address: rt.Address.String(), Status: rt.Status}
	for _, l := range links {
		name := ""
		if h, err := c.st.GetHub(l.HubID); err == nil {
			name = h.Name
		} else {
			slog.Warn("hub name not read", "hub", l.HubID, "err", err)
		}
		v.Hubs = append(v.Hubs, RouterHub{HubID: l.HubID, Name: name, Priority: l.Priority, SyncState: l.SyncState})
	}
	for _, e := range events {
		v.Events = append(v.Events, eventView(e))
	}
	c.mu.Lock()
	if hubID, ok := c.active[id]; ok {
		v.ActiveHubID = &hubID
	}
	if at, ok := c.handshakes[id]; ok {
		v.LastHandshakeAt = &at
	}
	c.mu.Unlock()
	return v, nil
}

func eventView(e store.RouterEvent) RouterEvent {
	out := RouterEvent{At: e.At}
	if e.FromHubID != "" {
		out.FromHubID = &e.FromHubID
	}
	if e.ToHubID != "" {
		out.ToHubID = &e.ToHubID
	}
	return out
}
