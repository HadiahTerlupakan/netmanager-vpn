// Command netmanager-vpn runs either the VPN core or a regional hub.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const (
	defaultState    = "/var/lib/netmanager-vpn/state.db"
	apiPort         = "7480"
	shutdownTimeout = 10 * time.Second
	readHeaderLimit = 5 * time.Second
	ioLimit         = 15 * time.Second
)

type config struct {
	EncryptionKey string
	APIToken      string
	CoreEndpoint  string
	InstallURL    string
	StatePath     string
}

// loadConfig reads the environment. The core needs more than a hub, so the
// mode decides which variables are required.
func loadConfig(mode string, getenv func(string) string) (config, error) {
	cfg := config{
		EncryptionKey: getenv("NMVPN_ENCRYPTION_KEY"), APIToken: getenv("NMVPN_API_TOKEN"),
		CoreEndpoint: getenv("NMVPN_CORE_ENDPOINT"), InstallURL: getenv("NMVPN_INSTALL_URL"),
		StatePath: getenv("NMVPN_STATE"),
	}
	if cfg.StatePath == "" {
		cfg.StatePath = defaultState
	}
	required := map[string]string{"NMVPN_ENCRYPTION_KEY": cfg.EncryptionKey}
	switch mode {
	case "hub":
	case "core":
		required["NMVPN_API_TOKEN"] = cfg.APIToken
		required["NMVPN_CORE_ENDPOINT"] = cfg.CoreEndpoint
		required["NMVPN_INSTALL_URL"] = cfg.InstallURL
	default:
		return config{}, fmt.Errorf("unknown mode %q (want core or hub)", mode)
	}
	for _, name := range []string{"NMVPN_ENCRYPTION_KEY", "NMVPN_API_TOKEN", "NMVPN_CORE_ENDPOINT", "NMVPN_INSTALL_URL"} {
		if v, ok := required[name]; ok && v == "" {
			return config{}, fmt.Errorf("%s is required in %s mode", name, mode)
		}
	}
	return cfg, nil
}

func main() {
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	mode := flag.String("mode", "", "core or hub")
	flag.Parse()
	args := flag.Args()

	var err error
	switch {
	case len(args) == 3 && args[0] == "hub" && args[1] == "join":
		err = joinHub(args[2])
	case len(args) == 0 && *mode != "":
		err = serve(*mode)
	default:
		fmt.Fprintln(os.Stderr, "usage: netmanager-vpn -mode core|hub | netmanager-vpn hub join <bundle>")
		os.Exit(2)
	}
	if err != nil {
		slog.Error("netmanager-vpn failed", "err", err)
		os.Exit(1)
	}
}

func serve(mode string) error {
	cfg, err := loadConfig(mode, os.Getenv)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if mode == "core" {
		return runCore(ctx, cfg)
	}
	return runHub(ctx, cfg)
}

// listen serves h on addr until ctx ends, then drains for shutdownTimeout.
func listen(ctx context.Context, addr string, h http.Handler) error {
	srv := &http.Server{Addr: addr, Handler: h, ReadHeaderTimeout: readHeaderLimit,
		ReadTimeout: ioLimit, WriteTimeout: ioLimit}
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	shutCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// every runs fn at each interval until ctx ends.
func every(ctx context.Context, interval time.Duration, fn func()) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn()
		}
	}
}
