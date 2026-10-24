package ppp

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// fakeCLI accepts one connection, records everything the client sent until it
// half-closed, and answers with reply.
func fakeCLI(t *testing.T, reply string) (addr string, got <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ch := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		in, _ := io.ReadAll(bufio.NewReader(c))
		ch <- string(in)
		_, _ = io.WriteString(c, reply)
	}()
	return ln.Addr().String(), ch
}

func cliSupervisor(t *testing.T, addr string) *Supervisor {
	t.Helper()
	s, _, _ := testSupervisor(t)
	s.cliAddr = addr
	return s
}

func TestTerminateSpeaksCLIProtocol(t *testing.T) {
	addr, got := fakeCLI(t, "1.13.0\r\n")
	s := cliSupervisor(t, addr)
	if err := s.Terminate(netip.MustParseAddr("10.100.0.10")); err != nil {
		t.Fatal(err)
	}
	want := s.cliPassword + "\nterminate ip 10.100.0.10\nshow version\n"
	if sent := <-got; sent != want {
		t.Fatalf("sent %q, want %q", sent, want)
	}
}

func TestTerminateReportsRejectedPassword(t *testing.T) {
	addr, _ := fakeCLI(t, "")
	if err := cliSupervisor(t, addr).Terminate(netip.MustParseAddr("10.100.0.10")); err == nil {
		t.Fatal("a connection closed without the version line must be an error")
	}
}

func TestTerminateReportsCommandError(t *testing.T) {
	addr, _ := fakeCLI(t, "invalid argument\r\n1.13.0\r\n")
	if err := cliSupervisor(t, addr).Terminate(netip.MustParseAddr("10.100.0.10")); err == nil {
		t.Fatal("accel-ppp's error reply was accepted")
	}
}

func TestSupervisorRendersCLIPasswordIntoDaemonConf(t *testing.T) {
	s, _, dir := testSupervisor(t)
	other, _, _ := testSupervisor(t)
	if !regexp.MustCompile(`^[A-Z2-7]{26}$`).MatchString(s.cliPassword) || s.cliPassword == other.cliPassword {
		t.Fatalf("passwords %q and %q", s.cliPassword, other.cliPassword)
	}
	if err := s.Apply("s", "i", "[modules]\n"); err != nil {
		t.Fatal(err)
	}
	conf, err := os.ReadFile(filepath.Join(dir, daemonFile))
	if err != nil {
		t.Fatal(err)
	}
	if want := "[modules]\n\n[cli]\ntcp=127.0.0.1:2001\npassword=" + s.cliPassword + "\n"; string(conf) != want {
		t.Fatalf("conf = %q", conf)
	}
	if strings.Contains(strings.Join(s.accel.cmd.Args, " "), s.cliPassword) {
		t.Fatal("password on the daemon's argv")
	}
}
