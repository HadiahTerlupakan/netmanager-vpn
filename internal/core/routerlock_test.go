package core

import "testing"

func TestRouterLocksForgetReleasedRouters(t *testing.T) {
	var l routerLocks
	unlockA := l.lock("a")
	unlockB := l.lock("b")
	unlockA()
	if _, ok := l.locks["a"]; ok || len(l.locks) != 1 {
		t.Fatalf("locks %v", l.locks)
	}
	unlockB()
	if len(l.locks) != 0 {
		t.Fatalf("locks %v", l.locks)
	}
}
