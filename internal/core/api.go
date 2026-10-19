package core

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const maxBodyBytes = 16 << 10

// Handler serves the control API. Every route but /healthz needs the bearer
// token. Responses for the RouterOS script and the admin config carry private
// keys, so nothing here logs a response body.
func (c *Core) Handler(token string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", c.healthz)
	mux.HandleFunc("GET /v1/hubs", c.listHubs)
	mux.HandleFunc("POST /v1/hubs", c.createHub)
	mux.HandleFunc("POST /v1/hubs/{id}/reissue", c.reissueHub)
	mux.HandleFunc("GET /v1/hubs/{id}/upgrade-command", c.hubUpgradeCommand)
	mux.HandleFunc("DELETE /v1/hubs/{id}", c.deleteHub)
	mux.HandleFunc("POST /v1/routers", c.createRouter)
	mux.HandleFunc("GET /v1/routers/{id}", c.getRouter)
	mux.HandleFunc("PUT /v1/routers/{id}/hubs", c.setRouterHubs)
	mux.HandleFunc("POST /v1/routers/{id}/claim", c.claimRouter)
	mux.HandleFunc("DELETE /v1/routers/{id}", c.deleteRouter)
	mux.HandleFunc("GET /v1/routers/{id}/routeros", c.routerScript)
	mux.HandleFunc("GET /v1/admin-peers", c.listAdminPeers)
	mux.HandleFunc("POST /v1/admin-peers", c.createAdminPeer)
	mux.HandleFunc("DELETE /v1/admin-peers/{id}", c.deleteAdminPeer)
	mux.HandleFunc("GET /v1/admin-peers/{id}/config", c.adminConfig)
	return bearer(token, mux)
}

func bearer(token string, next http.Handler) http.Handler {
	want := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			got, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if !ok || len(want) == 0 || subtle.ConstantTimeCompare([]byte(got), want) != 1 {
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (c *Core) healthz(w http.ResponseWriter, _ *http.Request) {
	if c.Healthy(c.cfg.Now()) {
		w.WriteHeader(http.StatusOK)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		slog.Warn("response not written", "err", err)
	}
}

func writeText(w http.ResponseWriter, s string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(s))
}

// writeErr maps a core or store error to its status. Only validation text
// reaches the caller; anything else is logged and answered opaquely.
func writeErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, ErrValidation):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "validation", "message": err.Error()})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
	case errors.Is(err, store.ErrInUse):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "in_use"})
	case errors.Is(err, store.ErrConflict):
		writeJSON(w, http.StatusConflict, map[string]string{"error": "conflict"})
	default:
		slog.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
	}
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErr(w, r, fmt.Errorf("%w: request body: %v", ErrValidation, err))
		return false
	}
	return true
}

// reply writes v as JSON, or the error if one occurred.
func reply(w http.ResponseWriter, r *http.Request, v any, err error) {
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func noContent(w http.ResponseWriter, r *http.Request, err error) {
	if err != nil {
		writeErr(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (c *Core) listHubs(w http.ResponseWriter, r *http.Request) {
	v, err := c.ListHubs()
	reply(w, r, v, err)
}

func (c *Core) createHub(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name       string `json:"name"`
		PublicHost string `json:"publicHost"`
		ListenPort int    `json:"listenPort"`
	}
	if !decode(w, r, &in) {
		return
	}
	h, cmd, err := c.CreateHub(in.Name, in.PublicHost, in.ListenPort)
	if err != nil {
		writeErr(w, r, err)
		return
	}
	view := HubView{ID: h.ID, Name: h.Name, PublicHost: h.PublicHost, ListenPort: h.ListenPort,
		Status: h.Status, LastSeenAt: h.LastSeenAt}
	writeJSON(w, http.StatusOK, map[string]any{"hub": view, "installCommand": cmd})
}

func (c *Core) reissueHub(w http.ResponseWriter, r *http.Request) {
	cmd, err := c.ReissueJoin(r.PathValue("id"))
	reply(w, r, map[string]string{"installCommand": cmd}, err)
}

func (c *Core) hubUpgradeCommand(w http.ResponseWriter, r *http.Request) {
	cmd, err := c.UpgradeCommand(r.PathValue("id"))
	if err != nil {
		writeErr(w, r, err)
		return
	}
	writeText(w, cmd)
}

func (c *Core) deleteHub(w http.ResponseWriter, r *http.Request) {
	noContent(w, r, c.DeleteHub(r.PathValue("id")))
}
