package ppp

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	charonPath  = "/usr/lib/strongswan/charon"
	swanctlPath = "swanctl"
	accelPath   = "accel-pppd"
	accelCmd    = "accel-cmd"

	secretsFile    = "chap-secrets"
	swanctlFile    = "swanctl.conf"
	daemonFile     = "accel-ppp.conf"
	strongswanFile = "strongswan.conf"

	restartBackoff = 5 * time.Second
	// charon opens its vici socket a moment after it starts; swanctl fails
	// until then, so loading is retried for as long as the spike waited.
	loadTimeout = 10 * time.Second
	loadPoll    = 200 * time.Millisecond
)

type child struct {
	cmd Command
	// ready runs once the process has started; an error kills it.
	ready func() error
	proc  Process
	alive bool
}

// Supervisor keeps charon and accel-pppd running on the configuration it was
// last given. Processes start on the first Apply, since before that there is
// nothing to serve.
type Supervisor struct {
	dir     string
	run     Runner
	backoff time.Duration

	mu                     sync.Mutex
	charon, accel          *child
	secrets, ipsec, daemon string
	loaded                 string // the ipsec content swanctl last loaded
	started, closed        bool
	done                   chan struct{}
}

// NewSupervisor returns a supervisor that keeps its files in dir.
func NewSupervisor(dir string) *Supervisor {
	return newSupervisor(dir, ExecRunner{}, restartBackoff)
}

func newSupervisor(dir string, run Runner, backoff time.Duration) *Supervisor {
	s := &Supervisor{dir: dir, run: run, backoff: backoff, done: make(chan struct{})}
	env := []string{"STRONGSWAN_CONF=" + s.path(strongswanFile)}
	s.charon = &child{cmd: Command{Path: charonPath, Env: env}, ready: s.loadIPsec}
	s.accel = &child{cmd: Command{Path: accelPath, Args: []string{"-c", s.path(daemonFile)}}}
	return s
}

func (s *Supervisor) path(name string) string { return filepath.Join(s.dir, name) }

// SecretsPath is the chap-secrets file the daemon configuration must name.
func (s *Supervisor) SecretsPath() string { return s.path(secretsFile) }

// Running reports whether both daemons are up and IPsec is loaded.
func (s *Supervisor) Running() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.charon.alive && s.accel.alive
}

// Apply writes the three files and brings the daemons in line: IPsec is
// reloaded only when its configuration differs from what was loaded, and
// accel-pppd restarts only when its own configuration changes. chap-secrets
// needs neither, as accel-ppp reads it on every login.
func (s *Supervisor) Apply(secrets, ipsec, daemon string) error {
	s.mu.Lock()
	if err := s.writeAll(secrets, ipsec, daemon); err != nil {
		s.mu.Unlock()
		return err
	}
	daemonChanged := daemon != s.daemon
	s.secrets, s.ipsec, s.daemon = secrets, ipsec, daemon
	if !s.started {
		s.started = true
		go s.supervise(s.charon)
		go s.supervise(s.accel)
		s.mu.Unlock()
		return nil
	}
	reload := s.charon.alive && s.loaded != ipsec
	var restart Process
	if daemonChanged {
		restart = s.accel.proc
	}
	s.mu.Unlock()
	if restart != nil {
		// Its supervise loop starts it again on the new file.
		_ = restart.Kill()
	}
	if reload {
		return s.loadIPsec()
	}
	return nil
}

func (s *Supervisor) writeAll(secrets, ipsec, daemon string) error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("ppp: %w", err)
	}
	files := []struct{ name, now, was string }{
		{strongswanFile, strongswanConf, ""},
		{secretsFile, secrets, s.secrets},
		{swanctlFile, ipsec, s.ipsec},
		{daemonFile, daemon, s.daemon},
	}
	for _, f := range files {
		if s.started && f.now == f.was {
			continue
		}
		if err := writePrivate(s.path(f.name), f.now); err != nil {
			return err
		}
	}
	return nil
}

// writePrivate replaces path through a rename, so accel-ppp opening the file
// for a login never reads it half written.
func writePrivate(path, content string) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		return fmt.Errorf("ppp: write %s: %w", filepath.Base(path), err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("ppp: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// loadIPsec makes charon load the connection and PSK; charon starts empty.
func (s *Supervisor) loadIPsec() error {
	s.mu.Lock()
	want := s.ipsec
	s.mu.Unlock()
	cmd := Command{Path: swanctlPath, Args: []string{"--load-all", "--file", s.path(swanctlFile)}, Env: s.charon.cmd.Env}
	deadline := time.Now().Add(loadTimeout)
	for {
		err := s.run.Run(cmd)
		if err == nil {
			s.mu.Lock()
			s.loaded = want
			s.mu.Unlock()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ppp: load IPsec: %w", err)
		}
		time.Sleep(loadPoll)
	}
}

func (s *Supervisor) supervise(c *child) {
	for {
		s.runOnce(c)
		select {
		case <-s.done:
			return
		case <-time.After(s.backoff):
		}
	}
}

func (s *Supervisor) runOnce(c *child) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	proc, err := s.run.Start(c.cmd)
	if err != nil {
		s.mu.Unlock()
		slog.Error("ppp: start failed", "cmd", c.cmd.Path, "err", err)
		return
	}
	c.proc = proc
	s.mu.Unlock()
	ok := true
	if c.ready != nil {
		if err := c.ready(); err != nil {
			slog.Error("ppp: not ready, restarting", "cmd", c.cmd.Path, "err", err)
			_ = proc.Kill()
			ok = false
		}
	}
	s.setAlive(c, ok)
	err = proc.Wait()
	s.mu.Lock()
	c.alive, c.proc = false, nil
	s.mu.Unlock()
	slog.Warn("ppp: exited", "cmd", c.cmd.Path, "err", err)
}

func (s *Supervisor) setAlive(c *child, alive bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.alive = alive && !s.closed
}

// Close stops both daemons and keeps them stopped.
func (s *Supervisor) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	s.closed = true
	close(s.done)
	for _, c := range []*child{s.charon, s.accel} {
		if c.proc != nil {
			_ = c.proc.Kill()
		}
	}
}
