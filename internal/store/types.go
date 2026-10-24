package store

import (
	"net/netip"
	"time"
)

// Status and sync-state values stored in the database.
const (
	RouterStatusPending = "pending"
	RouterStatusActive  = "active"

	SyncStatePending = "pending"
	SyncStateSynced  = "synced"

	HubStatusPendingInstall = "pending_install"
	HubStatusOnline         = "online"
	HubStatusOffline        = "offline"
	HubStatusExpired        = "expired"
)

// Hub is a regional hub as seen by the core.
type Hub struct {
	ID            string
	Name          string
	PublicHost    string
	ListenPort    int
	BackhaulAddr  netip.Addr
	PublicKey     string
	PrivateKey    string // sealed
	APIToken      string
	Status        string
	JoinExpiresAt time.Time
	LastSeenAt    *time.Time
	CreatedAt     time.Time
	IPsecPSK      string   // sealed; empty until L2TP is enabled
	Protocols     []string // protocols the hub serves; never empty on read
}

// Router is a customer router. ReleasedAt is set once it is soft-deleted.
type Router struct {
	ID         string
	Label      string
	Ref        string
	Address    netip.Addr
	PublicKey  string
	PrivateKey string // sealed
	Status     string
	CreatedAt  time.Time
	ReleasedAt *time.Time

	Protocol    string
	PPPUser     string
	PPPPassword string // sealed
}

// RouterHub links a router to one of its hubs; lower Priority is preferred.
type RouterHub struct {
	RouterID  string
	HubID     string
	Priority  int
	SyncState string
}

// RouterEvent records a change of the hub carrying a router. FromHubID is
// empty for the first assignment.
type RouterEvent struct {
	ID        int64
	RouterID  string
	FromHubID string
	ToHubID   string
	At        time.Time
}

// AdminPeer is an operator's VPN peer on the admin subnet.
type AdminPeer struct {
	ID         string
	Label      string
	Address    netip.Addr
	PublicKey  string
	PrivateKey string // sealed
	CreatedAt  time.Time
}

// HubConfig is the single configuration row a hub keeps after joining.
type HubConfig struct {
	CorePublicKey string
	CoreEndpoint  string
	BackhaulAddr  netip.Addr
	ListenPort    int
	APIToken      string
	PrivateKeyUp  string // sealed
	PrivateKeyNM  string // sealed
	IPsecPSK      string // sealed
}

// Peer is a router peer registered on a hub.
type Peer struct {
	PublicKey string
	Address   netip.Addr
	CreatedAt time.Time

	Protocol    string
	PPPUser     string
	PPPPassword string // sealed
}
