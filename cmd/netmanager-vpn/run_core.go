package main

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/core"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/firewall"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/secret"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/wgdevice"
)

const (
	activeInterval  = 10 * time.Second
	expireInterval  = 10 * time.Minute
	syncInterval    = time.Minute
	corePanelListen = "0.0.0.0"
)

// runCore never tears down wg-core on exit: the tunnels must outlive a
// restart of this process.
func runCore(ctx context.Context, cfg config) error {
	box, err := secret.NewBox(cfg.EncryptionKey)
	if err != nil {
		return fmt.Errorf("NMVPN_ENCRYPTION_KEY: %w", err)
	}
	st, err := store.Open(cfg.StatePath)
	if err != nil {
		return err
	}
	defer st.Close()
	c := core.New(wgdevice.NewLinux(), st, box, core.NewHTTPHubClient(box),
		core.Config{CoreEndpoint: cfg.CoreEndpoint, InstallURL: cfg.InstallURL})
	if err := c.Init(); err != nil {
		return err
	}
	if err := firewall.NewNft().Apply(firewall.RenderCore()); err != nil {
		return fmt.Errorf("firewall: %w", err)
	}
	go c.RunActiveLoop(ctx, activeInterval)
	go every(ctx, expireInterval, func() {
		if n, err := c.ExpirePending(ctx, time.Now()); err != nil {
			slog.Error("expire pending routers failed", "err", err)
		} else if n > 0 {
			slog.Info("expired unclaimed routers", "count", n)
		}
	})
	go every(ctx, syncInterval, func() {
		if err := c.SyncPending(ctx); err != nil {
			slog.Error("sync pending peers failed", "err", err)
		}
	})
	slog.Info("core listening", "port", apiPort)
	return listen(ctx, net.JoinHostPort(corePanelListen, apiPort), c.Handler(cfg.APIToken))
}
