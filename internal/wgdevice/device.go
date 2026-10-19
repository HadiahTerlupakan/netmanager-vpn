package wgdevice

import "time"

// PeerConfig is one peer as the kernel needs it. An empty Endpoint leaves the
// peer's learned endpoint alone, which is what a NAT'd router peer needs.
type PeerConfig struct {
	PublicKey  string
	AllowedIPs []string
	Endpoint   string
	Keepalive  time.Duration
}

// Config is the complete desired state of the interface. There is no partial
// form on purpose: the service always applies everything.
type Config struct {
	InterfaceName string
	PrivateKey    string
	Address       string
	ListenPort    int
	MTU           int
	Peers         []PeerConfig
}

// PeerStatus is one peer's live state as read back from the kernel.
type PeerStatus struct {
	PublicKey       string
	LastHandshakeAt *time.Time
	RxBytes         int64
	TxBytes         int64
}

// Device is the boundary between decisions and the kernel. Everything above it
// is tested; the Linux implementation needs root and a Linux host.
type Device interface {
	Apply(cfg Config) error
	Status(iface string) ([]PeerStatus, error)
}
