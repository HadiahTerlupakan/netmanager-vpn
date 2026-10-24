package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/firewall"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/hub"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/ppp"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

const (
	maxBundleBytes    = 16 << 10
	reconcileRetry    = 10 * time.Second
	reconcileInterval = time.Minute
	// pppDir holds the daemons' files, PSK and PPP passwords among them. It is
	// on tmpfs: every start rewrites them from the store.
	pppDir = "/run/netmanager-vpn/ppp"
)

func openHub(cfg config) (*secret.Box, *store.Store, error) {
	box, err := secret.NewBox(cfg.EncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("NMVPN_ENCRYPTION_KEY: %w", err)
	}
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		return nil, nil, err
	}
	return box, st, nil
}

// pppOptions wires L2TP/IPsec when the kernel can carry it; otherwise the hub
// serves WireGuard alone and reports only that to the core. gw is the hub's
// end of every session, which tells its sessions from other PPP links.
func pppOptions(gw netip.Addr) (hub.Options, *ppp.Supervisor) {
	if !ppp.HostSupported("/") {
		slog.Info("hub serves WireGuard only: /dev/ppp or the l2tp_ppp module is missing")
		return hub.Options{}, nil
	}
	slog.Info("hub serves WireGuard and L2TP/IPsec")
	sup := ppp.NewSupervisor(pppDir)
	return hub.Options{Sessions: ppp.NewLinuxSessions(gw, sup), PPP: sup}, sup
}

// readBundle returns arg, or the bundle read from stdin when arg is "-": an
// argv element is visible in ps and docker inspect, and the bundle holds the
// hub's private key.
func readBundle(arg string, stdin io.Reader) (string, error) {
	if arg != "-" {
		return arg, nil
	}
	raw, err := io.ReadAll(io.LimitReader(stdin, maxBundleBytes))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

// joinHub is the one-shot install step: store the bundle, bring the
// interfaces up, exit.
func joinHub(arg string, stdin io.Reader) error {
	encoded, err := readBundle(arg, stdin)
	if err != nil {
		return err
	}
	cfg, err := loadConfig("hub", os.Getenv)
	if err != nil {
		return err
	}
	b, err := joinbundle.Decode(encoded)
	if err != nil {
		return err
	}
	// WireGuard-only: this process exits right after, and would leave any
	// daemon it started behind. `hub run` starts them.
	box, st, err := openHub(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	return hub.New(wgdevice.NewLinux(), st, firewall.NewNft(), box, hub.Options{}).Join(b)
}

func runHub(ctx context.Context, cfg config) error {
	box, st, err := openHub(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	hubCfg, err := st.LoadHubConfig()
	if errors.Is(err, store.ErrNotFound) {
		return errors.New("this hub has not joined yet: run `netmanager-vpn hub join <bundle>` first")
	}
	if err != nil {
		return err
	}
	opts, sup := pppOptions(hubCfg.BackhaulAddr)
	if sup != nil {
		defer sup.Close()
	}
	svc := hub.New(wgdevice.NewLinux(), st, firewall.NewNft(), box, opts)
	if !reconcileUntilOK(ctx, svc) {
		return nil
	}
	go every(ctx, reconcileInterval, func() {
		if err := svc.Reconcile(); err != nil {
			slog.Error("hub reconcile failed", "err", err)
		}
	})
	// The listener binds the backhaul address, which exists only once wg-up
	// does, hence the reconcile above comes first.
	addr := net.JoinHostPort(hubCfg.BackhaulAddr.String(), apiPort)
	slog.Info("hub listening", "addr", addr)
	return listen(ctx, addr, svc.Handler(hubCfg.APIToken))
}

// reconcileUntilOK retries until the first success; it reports false if ctx
// ended first.
func reconcileUntilOK(ctx context.Context, svc *hub.Service) bool {
	for {
		err := svc.Reconcile()
		if err == nil {
			return true
		}
		slog.Error("hub reconcile failed, retrying", "err", err)
		select {
		case <-ctx.Done():
			return false
		case <-time.After(reconcileRetry):
		}
	}
}
