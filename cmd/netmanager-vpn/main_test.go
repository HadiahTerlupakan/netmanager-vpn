package main

import (
	"strings"
	"testing"
)

func envOf(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestMainRequiresEnv(t *testing.T) {
	full := map[string]string{
		"NMVPN_ENCRYPTION_KEY": "k", "NMVPN_API_TOKEN": "t",
		"NMVPN_CORE_ENDPOINT": "vpn.example.com:51822", "NMVPN_INSTALL_URL": "https://x/install.sh",
		"NMVPN_HUB_IMAGE": "ghcr.io/x/netmanager-vpn:abc-1",
	}
	for _, missing := range []string{"NMVPN_ENCRYPTION_KEY", "NMVPN_API_TOKEN", "NMVPN_CORE_ENDPOINT", "NMVPN_INSTALL_URL", "NMVPN_HUB_IMAGE"} {
		env := map[string]string{}
		for k, v := range full {
			if k != missing {
				env[k] = v
			}
		}
		_, err := loadConfig("core", envOf(env))
		if err == nil || !strings.Contains(err.Error(), missing) {
			t.Fatalf("core without %s: %v", missing, err)
		}
	}
	if _, err := loadConfig("hub", envOf(map[string]string{})); err == nil || !strings.Contains(err.Error(), "NMVPN_ENCRYPTION_KEY") {
		t.Fatalf("hub without key: %v", err)
	}
	cfg, err := loadConfig("hub", envOf(map[string]string{"NMVPN_ENCRYPTION_KEY": "k"}))
	if err != nil || cfg.StatePath != defaultState {
		t.Fatalf("hub config %+v %v", cfg, err)
	}
	if _, err := loadConfig("bogus", envOf(full)); err == nil {
		t.Fatal("unknown mode accepted")
	}
}

func TestHubImageMustBePinned(t *testing.T) {
	for ref, ok := range map[string]bool{
		"ghcr.io/x/netmanager-vpn:abc123-1700000000":                 true,
		"ghcr.io/x/netmanager-vpn@sha256:" + strings.Repeat("a", 64): true,
		"localhost:5000/netmanager-vpn:v1":                           true,
		"ghcr.io/x/netmanager-vpn":                                   false,
		"localhost:5000/netmanager-vpn":                              false,
		"ghcr.io/x/netmanager-vpn:latest":                            false,
		"ghcr.io/x/netmanager-vpn:":                                  false,
	} {
		env := envOf(map[string]string{
			"NMVPN_ENCRYPTION_KEY": "k", "NMVPN_API_TOKEN": "t", "NMVPN_CORE_ENDPOINT": "h:1",
			"NMVPN_INSTALL_URL": "https://x", "NMVPN_HUB_IMAGE": ref,
		})
		_, err := loadConfig("core", env)
		if (err == nil) != ok {
			t.Errorf("%q: err=%v, want ok=%v", ref, err, ok)
		}
	}
}
