package ppp

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProc exits on Kill, and on Stop unless it ignores SIGTERM.
type fakeProc struct {
	once        sync.Once
	done        chan struct{}
	ignoresStop bool
	stops       atomic.Int32
	kills       atomic.Int32
}

func (p *fakeProc) Wait() error { <-p.done; return errors.New("exited") }
func (p *fakeProc) exit()       { p.once.Do(func() { close(p.done) }) }

func (p *fakeProc) Stop() error {
	p.stops.Add(1)
	if !p.ignoresStop {
		p.exit()
	}
	return nil
}

func (p *fakeProc) Kill() error {
	p.kills.Add(1)
	p.exit()
	return nil
}

// fakeRunner stands in for exec: started processes run until killed or
// exited by the test, and one-shot commands are recorded.
type fakeRunner struct {
	mu      sync.Mutex
	started []string
	procs   map[string]*fakeProc
	ran     []string
	// stubborn names the commands whose processes ignore SIGTERM.
	stubborn map[string]bool
}

func newFakeRunner() *fakeRunner { return &fakeRunner{procs: map[string]*fakeProc{}} }

func (r *fakeRunner) Start(c Command) (Process, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p := &fakeProc{done: make(chan struct{}), ignoresStop: r.stubborn[c.Path]}
	r.started = append(r.started, c.Path)
	r.procs[c.Path] = p
	return p, nil
}

func (r *fakeRunner) Run(c Command) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.ran = append(r.ran, strings.Join(append([]string{c.Path}, c.Args...), " "))
	return nil
}

func (r *fakeRunner) count(list func() []string, prefix string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range list() {
		if strings.HasPrefix(s, prefix) {
			n++
		}
	}
	return n
}

func (r *fakeRunner) loads() int {
	return r.count(func() []string { return r.ran }, "swanctl --load-all")
}
func (r *fakeRunner) starts(p string) int { return r.count(func() []string { return r.started }, p) }

func (r *fakeRunner) proc(path string) *fakeProc {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.procs[path]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func testSupervisor(t *testing.T) (*Supervisor, *fakeRunner, string) {
	t.Helper()
	dir := t.TempDir()
	r := newFakeRunner()
	s := newSupervisor(dir, r, 20*time.Millisecond)
	t.Cleanup(s.Close)
	return s, r, dir
}

func TestSupervisorWritesPrivateFilesAndStartsBoth(t *testing.T) {
	s, r, dir := testSupervisor(t)
	if s.Running() {
		t.Fatal("running before Apply")
	}
	if err := s.Apply("secrets\n", "ipsec\n", "daemon\n"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both children", s.Running)
	files := map[string]string{secretsFile: "secrets\n", swanctlFile: "ipsec\n", daemonFile: "daemon\n" + cliSection(s.cliPassword)}
	for name, want := range files {
		p := filepath.Join(dir, name)
		got, err := os.ReadFile(p)
		if err != nil || string(got) != want {
			t.Fatalf("%s = %q, %v", name, got, err)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v", name, fi.Mode().Perm())
		}
	}
	if r.starts(charonPath) != 1 || r.starts(accelPath) != 1 || r.loads() != 1 {
		t.Fatalf("started %v ran %v", r.started, r.ran)
	}
	if s.SecretsPath() != filepath.Join(dir, secretsFile) {
		t.Fatalf("SecretsPath = %s", s.SecretsPath())
	}
}

func TestSupervisorReloadsIPsecOnlyWhenItChanges(t *testing.T) {
	s, r, _ := testSupervisor(t)
	if err := s.Apply("s", "ipsec-1", "d"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", s.Running)
	if err := s.Apply("s2", "ipsec-1", "d"); err != nil {
		t.Fatal(err)
	}
	if r.loads() != 1 {
		t.Fatalf("same ipsec reloaded: %v", r.ran)
	}
	if err := s.Apply("s2", "ipsec-2", "d"); err != nil {
		t.Fatal(err)
	}
	if r.loads() != 2 {
		t.Fatalf("changed ipsec not reloaded: %v", r.ran)
	}
	if r.starts(accelPath) != 1 {
		t.Fatalf("accel-pppd restarted for a secrets change: %v", r.started)
	}
}

func TestSupervisorRestartsExitedChildAndReloadsIPsec(t *testing.T) {
	s, r, _ := testSupervisor(t)
	if err := s.Apply("s", "i", "d"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", s.Running)
	r.proc(charonPath).exit()
	waitFor(t, "charon restart", func() bool { return r.starts(charonPath) == 2 && s.Running() })
	if r.loads() != 2 {
		t.Fatalf("restarted charon not loaded: %v", r.ran)
	}
	r.proc(accelPath).exit()
	waitFor(t, "accel restart", func() bool { return r.starts(accelPath) == 2 && s.Running() })
}

func TestSupervisorRestartsAccelOnDaemonChange(t *testing.T) {
	s, r, _ := testSupervisor(t)
	if err := s.Apply("s", "i", "d1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", s.Running)
	if err := s.Apply("s", "i", "d2"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "accel restart", func() bool { return r.starts(accelPath) == 2 })
	if r.starts(charonPath) != 1 {
		t.Fatalf("charon restarted: %v", r.started)
	}
}

func TestSupervisorCloseStopsChildren(t *testing.T) {
	s, r, _ := testSupervisor(t)
	if err := s.Apply("s", "i", "d"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", s.Running)
	s.Close()
	waitFor(t, "stopped", func() bool { return !s.Running() })
	time.Sleep(60 * time.Millisecond)
	if r.starts(charonPath) != 1 || r.starts(accelPath) != 1 {
		t.Fatalf("restarted after Close: %v", r.started)
	}
}

// charon cleans its xfrm state up on SIGTERM, so Close asks first and kills
// only a daemon that has not exited within the grace period.
func TestSupervisorCloseAsksBeforeKilling(t *testing.T) {
	s, r, _ := testSupervisor(t)
	s.stopGrace = 50 * time.Millisecond
	r.stubborn = map[string]bool{accelPath: true}
	if err := s.Apply("s", "i", "d"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "running", s.Running)
	charon, accel := r.proc(charonPath), r.proc(accelPath)
	start := time.Now()
	s.Close()
	if charon.stops.Load() != 1 || charon.kills.Load() != 0 {
		t.Fatalf("charon: %d stops, %d kills; want SIGTERM only", charon.stops.Load(), charon.kills.Load())
	}
	if accel.stops.Load() != 1 || accel.kills.Load() != 1 {
		t.Fatalf("accel: %d stops, %d kills; want SIGTERM then SIGKILL", accel.stops.Load(), accel.kills.Load())
	}
	if waited := time.Since(start); waited < s.stopGrace {
		t.Fatalf("killed after %v, before the %v grace", waited, s.stopGrace)
	}
}
