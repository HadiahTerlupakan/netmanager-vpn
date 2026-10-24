package core

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

const (
	hubAPIPort    = "7480"
	hubAPITimeout = 5 * time.Second
	maxErrBody    = 512
	// A peer entry is about 150 bytes of JSON, so this holds some 200 000
	// routers; a truncated list would fail to parse and read as a lost hub.
	maxRespBody = 32 << 20
)

// ErrHubAddressInUse means the hub already carries another peer on that address.
var ErrHubAddressInUse = errors.New("core: hub says the address is in use")

// errHubNoRoute is a 404: on /v1/ipsec and /v1/info it means a hub built
// before L2TP, which serves WireGuard only.
var errHubNoRoute = errors.New("core: hub has no such route")

// PeerSpec is one router peer as a hub is told to carry it. PPPPassword is in
// the clear; it is sent only for L2TP.
type PeerSpec struct {
	PublicKey   string
	Address     netip.Addr
	Protocol    string
	PPPUser     string
	PPPPassword string
}

// HubInfo is what a hub reports about itself.
type HubInfo struct {
	Protocols []string
}

// peerBody, ipsecBody and infoBody mirror hub.PutPeerRequest,
// hub.PutIPsecRequest and hub.InfoResponse; the client contract test pins
// them together.
type peerBody struct {
	Address     string `json:"address"`
	Protocol    string `json:"protocol"`
	PPPUsername string `json:"pppUsername,omitempty"`
	PPPPassword string `json:"pppPassword,omitempty"`
}

type ipsecBody struct {
	PSK     string `json:"psk"`
	LocalID string `json:"localId"`
}

type infoBody struct {
	Protocols []string `json:"protocols"`
}

// HubPeerStatus mirrors the JSON of hub.PeerStatus. It is declared here so the
// core need not import the hub service; the client contract test pins the two
// together.
type HubPeerStatus struct {
	PublicKey       string     `json:"publicKey"`
	Address         string     `json:"address"`
	LastHandshakeAt *time.Time `json:"lastHandshakeAt"`
	RxBytes         int64      `json:"rxBytes"`
	TxBytes         int64      `json:"txBytes"`
}

// HubClient is the core's view of a hub's peer API.
type HubClient interface {
	UpsertPeer(ctx context.Context, hub store.Hub, spec PeerSpec) error
	DeletePeer(ctx context.Context, hub store.Hub, pub string) error
	Peers(ctx context.Context, hub store.Hub) ([]HubPeerStatus, error)
	// SetIPsecPSK gives the hub its L2TP pre-shared key, with its public host
	// as the IPsec identity. A hub without the route takes it as a no-op.
	SetIPsecPSK(ctx context.Context, hub store.Hub, psk string) error
	// Info reports the hub's protocols; a hub without the route is
	// WireGuard-only.
	Info(ctx context.Context, hub store.Hub) (HubInfo, error)
}

type httpHubClient struct {
	box     *secret.Box
	http    *http.Client
	baseURL func(store.Hub) string
}

// NewHTTPHubClient calls each hub's API over the backhaul. The box opens the
// hub's sealed bearer token.
func NewHTTPHubClient(box *secret.Box) HubClient {
	return newHTTPHubClient(box, func(h store.Hub) string {
		return "http://" + h.BackhaulAddr.String() + ":" + hubAPIPort
	})
}

func newHTTPHubClient(box *secret.Box, baseURL func(store.Hub) string) HubClient {
	return &httpHubClient{box: box, http: &http.Client{Timeout: hubAPITimeout}, baseURL: baseURL}
}

func (c *httpHubClient) UpsertPeer(ctx context.Context, h store.Hub, spec PeerSpec) error {
	body, _ := json.Marshal(peerBody{Address: spec.Address.String(), Protocol: spec.Protocol,
		PPPUsername: spec.PPPUser, PPPPassword: spec.PPPPassword})
	_, err := c.do(ctx, h, http.MethodPut, "/v1/peers/"+url.PathEscape(spec.PublicKey), body)
	return err
}

func (c *httpHubClient) SetIPsecPSK(ctx context.Context, h store.Hub, psk string) error {
	body, _ := json.Marshal(ipsecBody{PSK: psk, LocalID: h.PublicHost})
	_, err := c.do(ctx, h, http.MethodPut, "/v1/ipsec", body)
	if errors.Is(err, errHubNoRoute) {
		slog.Debug("hub predates L2TP; PSK not pushed", "hub", h.ID)
		return nil
	}
	return err
}

func (c *httpHubClient) Info(ctx context.Context, h store.Hub) (HubInfo, error) {
	raw, err := c.do(ctx, h, http.MethodGet, "/v1/info", nil)
	if errors.Is(err, errHubNoRoute) {
		return HubInfo{Protocols: []string{routeros.ProtocolWireGuard}}, nil
	}
	if err != nil {
		return HubInfo{}, err
	}
	var out infoBody
	if err := json.Unmarshal(raw, &out); err != nil {
		return HubInfo{}, fmt.Errorf("core: hub info: %w", err)
	}
	return HubInfo(out), nil
}

func (c *httpHubClient) DeletePeer(ctx context.Context, h store.Hub, pub string) error {
	_, err := c.do(ctx, h, http.MethodDelete, "/v1/peers/"+url.PathEscape(pub), nil)
	return err
}

func (c *httpHubClient) Peers(ctx context.Context, h store.Hub) ([]HubPeerStatus, error) {
	raw, err := c.do(ctx, h, http.MethodGet, "/v1/peers", nil)
	if err != nil {
		return nil, err
	}
	var out []HubPeerStatus
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("core: hub peers: %w", err)
	}
	return out, nil
}

func (c *httpHubClient) do(ctx context.Context, h store.Hub, method, path string, body []byte) ([]byte, error) {
	token, err := c.box.Open(h.APIToken)
	if err != nil {
		return nil, fmt.Errorf("core: open hub token: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL(h)+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if resp.StatusCode == http.StatusConflict && bytes.Contains(raw, []byte("address_in_use")) {
		return nil, ErrHubAddressInUse
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if len(raw) > maxErrBody {
			raw = raw[:maxErrBody]
		}
		err := fmt.Errorf("core: hub %s %s: status %d: %s", method, path, resp.StatusCode, bytes.TrimSpace(raw))
		if resp.StatusCode == http.StatusNotFound {
			err = errors.Join(errHubNoRoute, err)
		}
		return nil, err
	}
	return raw, nil
}
