package wgdevice

import (
	"slices"
	"sync"
)

// Memory records what would have been applied, so callers can be tested
// without a kernel.
type Memory struct {
	mu          sync.Mutex
	last        Config
	statuses    []PeerStatus
	unreachable []string
}

// NewMemory returns an empty in-memory device.
func NewMemory() *Memory {
	return &Memory{}
}

// Apply records cfg as the applied state.
func (m *Memory) Apply(cfg Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last = cfg
	return nil
}

// Status returns the statuses set with SetStatus.
func (m *Memory) Status(string) ([]PeerStatus, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.statuses, nil
}

// Last returns the most recently applied config.
func (m *Memory) Last() Config {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.last
}

// SetStatus presets what Status reports.
func (m *Memory) SetStatus(statuses []PeerStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.statuses = statuses
}

// EnsureUnreachable records prefix once.
func (m *Memory) EnsureUnreachable(prefix string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !slices.Contains(m.unreachable, prefix) {
		m.unreachable = append(m.unreachable, prefix)
	}
	return nil
}

// Unreachable returns the prefixes EnsureUnreachable was asked for.
func (m *Memory) Unreachable() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.unreachable)
}
