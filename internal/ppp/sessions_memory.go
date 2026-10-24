package ppp

import (
	"net/netip"
	"sync"
)

// MemorySessions is a Sessions for tests: SetLive presets the sessions and
// Terminate removes one and records it.
type MemorySessions struct {
	mu         sync.Mutex
	live       map[netip.Addr]bool
	liveErr    error
	terminated []netip.Addr
}

// NewMemorySessions returns a MemorySessions with no sessions.
func NewMemorySessions() *MemorySessions {
	return &MemorySessions{live: map[netip.Addr]bool{}}
}

// SetLive replaces the live sessions with addrs.
func (m *MemorySessions) SetLive(addrs ...netip.Addr) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.live = map[netip.Addr]bool{}
	for _, a := range addrs {
		m.live[a] = true
	}
}

// FailLive makes Live return err; nil restores it.
func (m *MemorySessions) FailLive(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.liveErr = err
}

// Live returns a copy of the live sessions.
func (m *MemorySessions) Live() (map[netip.Addr]bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.liveErr != nil {
		return nil, m.liveErr
	}
	out := make(map[netip.Addr]bool, len(m.live))
	for a := range m.live {
		out[a] = true
	}
	return out, nil
}

// Terminate ends the session at addr.
func (m *MemorySessions) Terminate(addr netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.live, addr)
	m.terminated = append(m.terminated, addr)
	return nil
}

// Terminated lists every address Terminate was called with, in order.
func (m *MemorySessions) Terminated() []netip.Addr {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]netip.Addr(nil), m.terminated...)
}
