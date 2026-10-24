// Package ppp runs the hub's L2TP/IPsec side: strongSwan carries IPsec,
// accel-ppp terminates L2TP and PPP, and both are child processes of the hub.
package ppp

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/hadiahterlupakan/netmanager-vpn/internal/routeros"
	"github.com/hadiahterlupakan/netmanager-vpn/internal/store"
)

// The rules the core's credentials follow. They also keep every value free of
// quotes, whitespace and braces, which is what makes the files below safe to
// render by concatenation.
var (
	UserRE     = regexp.MustCompile(`^nmvpn-[0-9a-f]{1,64}$`)
	PasswordRE = regexp.MustCompile(`^[A-Za-z0-9_-]{24,64}$`)
	PSKRE      = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)
)

// HostSupported reports whether the kernel under root can carry L2TP sessions:
// accel-ppp needs the /dev/ppp device and the l2tp_ppp module.
func HostSupported(root string) bool {
	for _, p := range []string{"dev/ppp", "sys/module/l2tp_ppp"} {
		if _, err := os.Stat(filepath.Join(root, p)); err != nil {
			return false
		}
	}
	return true
}

// RenderSecrets returns accel-ppp's chap-secrets: one line per L2TP peer,
// binding its login to its router address. open unseals a stored password.
func RenderSecrets(peers []store.Peer, open func(string) (string, error)) (string, error) {
	var b strings.Builder
	for _, p := range peers {
		if p.Protocol != routeros.ProtocolL2TP {
			continue
		}
		pass, err := open(p.PPPPassword)
		if err != nil {
			return "", fmt.Errorf("ppp: open password of %s: %w", p.PPPUser, err)
		}
		// A stored row reached here through the API's validation; checking
		// again keeps one bad row from adding a line that logs in elsewhere.
		if !UserRE.MatchString(p.PPPUser) || !PasswordRE.MatchString(pass) || !p.Address.Is4() {
			return "", fmt.Errorf("ppp: peer %s has an invalid PPP login", p.PublicKey)
		}
		fmt.Fprintf(&b, "\"%s\" * \"%s\" %s\n", p.PPPUser, pass, p.Address)
	}
	return b.String(), nil
}

// RenderIPsec returns the swanctl configuration: IKEv1 with a PSK, transport
// mode carrying only L2TP. The proposals are the spike's (RouterOS's default
// l2tp-client settled on AES-128/SHA1/MODP2048 for IKE and AES-256/SHA1 with
// MODP1024 PFS for ESP); both PFS and non-PFS ESP variants are offered.
func RenderIPsec(psk, localID string) (string, error) {
	if !PSKRE.MatchString(psk) {
		return "", errors.New("ppp: invalid IPsec PSK")
	}
	if !routeros.ValidHost(localID) {
		return "", errors.New("ppp: invalid IPsec local id")
	}
	return fmt.Sprintf(ipsecTemplate, localID, psk), nil
}

const ipsecTemplate = `connections {
	nmvpn-l2tp {
		version = 1
		aggressive = no
		local_addrs = %%any
		proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha256-modp1024,aes256-sha1-modp1024,aes128-sha1-modp1024
		dpd_delay = 30s
		local {
			auth = psk
			id = %s
		}
		remote {
			auth = psk
		}
		children {
			nmvpn-l2tp {
				mode = transport
				local_ts = dynamic[udp/1701]
				remote_ts = dynamic[udp]
				esp_proposals = aes256-sha256-modp2048,aes256-sha1-modp2048,aes128-sha256-modp2048,aes128-sha1-modp2048,aes256-sha1-modp1024,aes128-sha1-modp1024,aes256-sha256,aes256-sha1,aes128-sha256,aes128-sha1
				dpd_action = clear
			}
		}
	}
}
secrets {
	ike-nmvpn {
		secret = "%s"
	}
}
`

// strongswanConf extends the image's strongswan.conf, whose includes load the
// plugins. Routes stay off because the PPP interface, not the IPsec SA, is
// what routes a router's address.
const strongswanConf = `include /etc/strongswan.conf
charon {
	install_routes = no
	filelog {
		stderr {
			default = 1
			ike = 2
			time_format = %T
		}
	}
}
`

// RenderDaemon returns accel-ppp's configuration. gw is the hub's end of every
// session; secretsPath is the chap-secrets file, which accel-ppp opens on each
// login, so rewriting it needs no reload.
//
// Only MS-CHAPv2 is loaded, so nothing weaker is offered; CCP is off because
// IPsec already encrypts. accel-ppp rejects every L2TP call whose source is
// outside [client-ip-range], and with 0.0.0.0/0 it disables its guard against
// tunnelling L2TP to an address inside a PPP session (a kernel soft lockup),
// so the range is everything but 10.0.0.0/8, where every session address is.
func RenderDaemon(gw netip.Addr, secretsPath string) string {
	return fmt.Sprintf(daemonTemplate, gw, secretsPath)
}

const daemonTemplate = `[modules]
log_file
l2tp
auth_mschap_v2
chap-secrets

[core]
log-error=/dev/stderr
thread-count=2

[common]
single-session=replace

[ppp]
verbose=1
min-mtu=1280
mtu=1380
mru=1380
ccp=0
ipv4=require
ipv6=deny
lcp-echo-interval=30
lcp-echo-failure=4

[l2tp]
verbose=1
ifname=ppp%%d

[chap-secrets]
gw-ip-address=%s
chap-secrets=%s

[log]
log-file=/dev/stdout
level=4

[cli]
tcp=127.0.0.1:2001

[client-ip-range]
0.0.0.0/5
8.0.0.0/7
11.0.0.0/8
12.0.0.0/6
16.0.0.0/4
32.0.0.0/3
64.0.0.0/2
128.0.0.0/1
`
