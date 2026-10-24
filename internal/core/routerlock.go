package core

import "sync"

// routerLocks hands out one mutex per router ID. An entry lives only while
// someone holds or waits for it, so the map stays as small as the number of
// routers being worked on at once.
type routerLocks struct {
	mu    sync.Mutex
	locks map[string]*routerLock
}

type routerLock struct {
	sync.Mutex
	refs int
}

// lock blocks until the router's mutex is held and returns its release.
func (l *routerLocks) lock(id string) (unlock func()) {
	l.mu.Lock()
	if l.locks == nil {
		l.locks = map[string]*routerLock{}
	}
	m := l.locks[id]
	if m == nil {
		m = &routerLock{}
		l.locks[id] = m
	}
	m.refs++
	l.mu.Unlock()
	m.Lock()
	return func() {
		m.Unlock()
		l.mu.Lock()
		if m.refs--; m.refs == 0 {
			delete(l.locks, id)
		}
		l.mu.Unlock()
	}
}
