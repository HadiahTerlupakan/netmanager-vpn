package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/firewall"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/hub"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/joinbundle"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

const (
	reconcileRetry    = 10 * time.Second
	reconcileInterval = time.Minute
)

func newHub(cfg config) (*hub.Service, *store.Store, error) {
	box, err := secret.NewBox(cfg.EncryptionKey)
	if err != nil {
		return nil, nil, fmt.Errorf("NMVPN_ENCRYPTION_KEY: %w", err)
	}
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		return nil, nil, err
	}
	return hub.New(wgdevice.NewLinux(), st, firewall.NewNft(), box, hub.Options{}), st, nil
}

// joinHub is the one-shot install step: store the bundle, bring the
// interfaces up, exit.
func joinHub(encoded string) error {
	cfg, err := loadConfig("hub", os.Getenv)
	if err != nil {
		return err
	}
	b, err := joinbundle.Decode(encoded)
	if err != nil {
		return err
	}
	svc, st, err := newHub(cfg)
	if err != nil {
		return err
	}
	defer st.Close()
	return svc.Join(b)
}

func runHub(ctx context.Context, cfg config) error {
	svc, st, err := newHub(cfg)
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
