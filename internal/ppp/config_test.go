package ppp

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

func plain(s string) (string, error) { return s, nil }

const goodPass = "abcdefghijklmnopqrstuvwx"

func TestRenderSecretsOneLinePerL2TPPeer(t *testing.T) {
	peers := []store.Peer{
		{PublicKey: "a", Address: netip.MustParseAddr("10.100.0.10"), Protocol: "l2tp", PPPUser: "nmvpn-0a", PPPPassword: goodPass},
		{PublicKey: "b", Address: netip.MustParseAddr("10.100.0.11"), Protocol: "wireguard"},
		{PublicKey: "c", Address: netip.MustParseAddr("10.100.0.12"), Protocol: "l2tp", PPPUser: "nmvpn-0c", PPPPassword: goodPass + "_-"},
	}
	got, err := RenderSecrets(peers, plain)
	if err != nil {
		t.Fatal(err)
	}
	want := `"nmvpn-0a" * "` + goodPass + `" 10.100.0.10` + "\n" +
		`"nmvpn-0c" * "` + goodPass + `_-" 10.100.0.12` + "\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
}

func TestRenderSecretsRefusesInjectedLine(t *testing.T) {
	for name, p := range map[string]store.Peer{
		"quote in password":   {PPPUser: "nmvpn-0a", PPPPassword: goodPass + `" 10.100.0.99` + "\n" + `"nmvpn-ff" * "x`},
		"newline in user":     {PPPUser: "nmvpn-0a\nnmvpn-0b", PPPPassword: goodPass},
		"space in user":       {PPPUser: "nmvpn-0a *", PPPPassword: goodPass},
		"short password":      {PPPUser: "nmvpn-0a", PPPPassword: "short"},
		"user without prefix": {PPPUser: "admin", PPPPassword: goodPass},
	} {
		p.Protocol, p.Address = "l2tp", netip.MustParseAddr("10.100.0.10")
		if out, err := RenderSecrets([]store.Peer{p}, plain); err == nil {
			t.Errorf("%s: rendered %q", name, out)
		}
	}
}

func TestRenderIPsecCarriesPSKAndLocalID(t *testing.T) {
	psk := strings.Repeat("k", 32)
	got, err := RenderIPsec(psk, "hub1.example.net")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"version = 1",
		"id = hub1.example.net",
		"mode = transport",
		"local_ts = dynamic[udp/1701]",
		"remote_ts = dynamic[udp]",
		"proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024",
		"esp_proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1",
		`secret = "` + psk + `"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
	for name, c := range map[string][2]string{
		"short psk":     {"short", "hub1.example.net"},
		"quoted psk":    {strings.Repeat("k", 32) + `"`, "hub1.example.net"},
		"bad local id":  {psk, "hub1.example.net\n}"},
		"ipv6 local id": {psk, "2001:db8::1"},
	} {
		if _, err := RenderIPsec(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRenderDaemonMatchesSpike(t *testing.T) {
	got := RenderDaemon(netip.MustParseAddr("10.99.0.2"), "/run/nmvpn/ppp/chap-secrets")
	for _, want := range []string{
		"[modules]\nlog_file\nl2tp\nauth_mschap_v2\nchap-secrets\n",
		"[common]\nsingle-session=replace\n",
		"mtu=1380\nmru=1380\nccp=0\nipv4=require\nipv6=deny\nlcp-echo-interval=30\nlcp-echo-failure=4\n",
		"[l2tp]\nverbose=1\nifname=ppp%d\n",
		"gw-ip-address=10.99.0.2\nchap-secrets=/run/nmvpn/ppp/chap-secrets\n",
		"[cli]\ntcp=127.0.0.1:2001\n",
		"[client-ip-range]\n0.0.0.0/5\n8.0.0.0/7\n11.0.0.0/8\n12.0.0.0/6\n16.0.0.0/4\n32.0.0.0/3\n64.0.0.0/2\n128.0.0.0/1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in\n%s", want, got)
		}
	}
}

func TestHostSupported(t *testing.T) {
	for name, c := range map[string]struct {
		files []string
		want  bool
	}{
		"neither":     {nil, false},
		"no module":   {[]string{"dev/ppp"}, false},
		"no /dev/ppp": {[]string{"sys/module/l2tp_ppp"}, false},
		"both":        {[]string{"dev/ppp", "sys/module/l2tp_ppp"}, true},
	} {
		root := t.TempDir()
		for _, f := range c.files {
			p := filepath.Join(root, f)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if got := HostSupported(root); got != c.want {
			t.Errorf("%s: got %v", name, got)
		}
	}
}
