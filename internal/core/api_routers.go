package core

import (
	"net/http"
)

func (c *Core) createRouter(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label    string   `json:"label"`
		HubIDs   []string `json:"hubIds"`
		Protocol string   `json:"protocol"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := c.CreateRouter(r.Context(), in.Label, in.HubIDs, in.Protocol)
	reply(w, r, v, err)
}

func (c *Core) getRouter(w http.ResponseWriter, r *http.Request) {
	v, err := c.GetRouter(r.PathValue("id"))
	reply(w, r, v, err)
}

func (c *Core) setRouterHubs(w http.ResponseWriter, r *http.Request) {
	var in struct {
		HubIDs []string `json:"hubIds"`
	}
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	if err := c.SetRouterHubs(r.Context(), id, in.HubIDs); err != nil {
		writeErr(w, r, err)
		return
	}
	v, err := c.GetRouter(id)
	reply(w, r, v, err)
}

func (c *Core) claimRouter(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Ref string `json:"ref"`
	}
	if !decode(w, r, &in) {
		return
	}
	id := r.PathValue("id")
	if err := c.ClaimRouter(id, in.Ref); err != nil {
		writeErr(w, r, err)
		return
	}
	v, err := c.GetRouter(id)
	reply(w, r, v, err)
}

func (c *Core) deleteRouter(w http.ResponseWriter, r *http.Request) {
	noContent(w, r, c.DeleteRouter(r.Context(), r.PathValue("id")))
}

func (c *Core) routerScript(w http.ResponseWriter, r *http.Request) {
	s, err := c.RouterScript(r.PathValue("id"), r.URL.Query().Get("part"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeText(w, s)
}

type protocolRequest struct {
	Protocol string `json:"protocol"`
}

func (c *Core) protocolScript(w http.ResponseWriter, r *http.Request) {
	var in protocolRequest
	if !decode(w, r, &in) {
		return
	}
	s, err := c.ProtocolScript(r.PathValue("id"), in.Protocol)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeText(w, s)
}

func (c *Core) setRouterProtocol(w http.ResponseWriter, r *http.Request) {
	var in protocolRequest
	if !decode(w, r, &in) {
		return
	}
	v, err := c.SetRouterProtocol(r.Context(), r.PathValue("id"), in.Protocol)
	reply(w, r, v, err)
}

func (c *Core) firstServer(w http.ResponseWriter, r *http.Request) {
	v, err := c.FirstServer(r.PathValue("id"))
	reply(w, r, v, err)
}

func (c *Core) listAdminPeers(w http.ResponseWriter, r *http.Request) {
	v, err := c.ListAdminPeers()
	reply(w, r, v, err)
}

func (c *Core) createAdminPeer(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Label string `json:"label"`
	}
	if !decode(w, r, &in) {
		return
	}
	v, err := c.CreateAdminPeer(in.Label)
	reply(w, r, v, err)
}

func (c *Core) deleteAdminPeer(w http.ResponseWriter, r *http.Request) {
	noContent(w, r, c.DeleteAdminPeer(r.PathValue("id")))
}

func (c *Core) adminConfig(w http.ResponseWriter, r *http.Request) {
	s, err := c.AdminConfig(r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeText(w, s)
}
