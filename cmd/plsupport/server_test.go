package main

import "net"

import "testing"

// The -server= flag chooses which server tells the customer WHO is asking to connect, where
// the tunnel dials, and what password guards their screen. Every vector below was raised
// against this function during the 2026-09-04 adversarial review; each one that gets through
// hands an attacker our code signature. A failure here is not a style regression.
func TestAllowedServerRejectsEverythingButOurHosts(t *testing.T) {
	reject := []string{
		// wrong scheme
		"http://app.proxylink.dev",
		"ftp://app.proxylink.dev",
		"//app.proxylink.dev",
		"app.proxylink.dev",
		// lookalike registrable domains
		"https://evilproxylink.dev",
		"https://proxylink.dev.attacker.com",
		"https://app.proxylink.dev.attacker.com",
		"https://xn--proxylink-.dev",
		// the host is in the path or the query, not the authority
		"https://attacker.com/app.proxylink.dev",
		"https://attacker.com/?x=app.proxylink.dev",
		"https://attacker.com#app.proxylink.dev",
		// userinfo tricks: the real host is after the @
		"https://app.proxylink.dev@evil.com",
		"https://evil.com@app.proxylink.dev",
		// separator confusion
		`https://app.proxylink.dev\@evil.com`,
		`https://evil.com\.proxylink.dev`,
		"https://app.proxylink.dev%2f.evil.com",
		// IDN homograph: Cyrillic а in "app"
		"https://аpp.proxylink.dev",
		// subdomains are no longer trusted, because a dangling CNAME anywhere in the zone
		// would otherwise be a full man in the middle
		"https://staging.proxylink.dev",
		"https://tcp.proxylink.dev",
		"https://anything.proxylink.dev",
		// a port would let a foothold on the host serve the answers
		"https://app.proxylink.dev:8443",
		// paths and fragments must not survive to be concatenated later
		"https://app.proxylink.dev/api",
		"https://app.proxylink.dev/?a=b",
		// nonsense
		"",
		"   ",
		"https://",
		"https://[::1]",
	}
	for _, in := range reject {
		if got, ok := allowedServer(in); ok {
			t.Errorf("allowedServer(%q) accepted and returned %q, must be rejected", in, got)
		}
	}

	accept := map[string]string{
		"https://app.proxylink.dev":  "https://app.proxylink.dev",
		"https://app.proxylink.dev/": "https://app.proxylink.dev",
		"https://APP.ProxyLink.dev":  "https://app.proxylink.dev",
		"https://app.proxylink.dev.": "https://app.proxylink.dev",
		"  https://proxylink.dev  ":  "https://proxylink.dev",
	}
	for in, want := range accept {
		got, ok := allowedServer(in)
		if !ok {
			t.Errorf("allowedServer(%q) rejected, must be accepted", in)
			continue
		}
		if got != want {
			t.Errorf("allowedServer(%q) = %q, want %q", in, got, want)
		}
	}
}

// ── VNC port selection ────────────────────────────────────────────────────────
//
// 2026-09-23: a customer's PC already ran TightVNC on 5900, so our UltraVNC never got the
// port. guacd connected to THEIR server, was refused, and the technician saw a blank screen.
// We do not take the port from them - CLAUDE.md is explicit that a service predating us is
// the customer's - so we step around it instead.

func TestPickVncPortsPrefers5900WhenFree(t *testing.T) {
	vnc, http, _ := pickVncPorts(0)
	if vnc != 5900 || http != 5800 {
		t.Fatalf("with nothing in the way we must not move: got %d/%d, want 5900/5800", vnc, http)
	}
}

func TestPickVncPortsStepsAroundAnOccupiedPort(t *testing.T) {
	// Stand in for the customer's TightVNC.
	squatter, err := net.Listen("tcp", "127.0.0.1:5900")
	if err != nil {
		t.Skip("5900 already in use on this machine; cannot run the occupied-port case")
	}
	defer squatter.Close()

	vnc, http, _ := pickVncPorts(0)
	if vnc == 5900 {
		t.Fatal("chose 5900 while something else was holding it")
	}
	if vnc < 5901 || vnc > 5919 {
		t.Fatalf("chose %d, outside the 5901-5919 range", vnc)
	}
	// The HTTP port must move WITH it. The machine that collides on 5900 is a good bet to
	// collide on 5800 too, and a winvnc that cannot bind its HTTP port loses the session.
	if http != vnc-100 {
		t.Fatalf("http port %d did not follow vnc port %d", http, vnc)
	}
}

func TestPickVncPortsReusesThePortWeAlreadyToldTheServer(t *testing.T) {
	// A mid-session restart must rebind the same port: /ready only accepts an update while
	// the session is pending, so drifting would strand the technician on a stale port.
	vnc, _, _ := pickVncPorts(5907)
	if vnc != 5907 {
		t.Fatalf("did not prefer the remembered port: got %d, want 5907", vnc)
	}
}

// The bug this file exists for: on 2026-09-23 a machine running TightVNC on 5900 got winvnc
// pointed at 5900 anyway. portFree was a BIND test, and on Windows a process holding
// 0.0.0.0:5900 leaves 127.0.0.1:5900 bindable — so the probe said "free" about a port that was
// actively serving. The fix is to ask the OS what is listening. This test is that question:
// the port is bindable here (nothing in this process holds it) and must still be refused.
func TestPickVncPortsRefusesAPortTheOsSaysIsListening(t *testing.T) {
	defer stubListeners(t, map[int]bool{5900: true})()

	vnc, http, _ := pickVncPorts(0)
	if vnc != 5901 || http != 5801 {
		t.Fatalf("a port with a live listener was handed out: got %d/%d, want 5901/5801", vnc, http)
	}
}

// The HTTP port has to move with it. A machine that collides on 5900 is a good bet to collide
// on 5800, and winvnc failing to bind its HTTP port loses the session just as thoroughly.
func TestPickVncPortsStepsPastAnOccupiedHttpPortToo(t *testing.T) {
	defer stubListeners(t, map[int]bool{5800: true})()

	vnc, http, _ := pickVncPorts(0)
	if vnc != 5901 || http != 5801 {
		t.Fatalf("stepped onto an occupied HTTP port: got %d/%d, want 5901/5801", vnc, http)
	}
}

// A machine we cannot interrogate must not be treated as an empty machine. When the listener
// query fails it returns nil, and nil means "no information" — the remaining probes decide.
func TestPickVncPortsStillWorksWhenTheOsCannotBeAsked(t *testing.T) {
	defer stubListeners(t, nil)()

	if vnc, http, _ := pickVncPorts(0); vnc != 5900 || http != 5800 {
		t.Fatalf("got %d/%d, want the default 5900/5800", vnc, http)
	}
}

// Anything that ANSWERS a connection is occupied, whatever the table says.
func TestPortFreeRefusesAPortThatAnswers(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen here: %v", err)
	}
	defer l.Close()

	port := l.Addr().(*net.TCPAddr).Port
	if portFree(port) {
		t.Fatalf("port %d has a live listener and was reported free", port)
	}
}

func stubListeners(t *testing.T, ports map[int]bool) func() {
	t.Helper()
	prev := platformListeners
	platformListeners = func() map[int]bool { return ports }
	return func() { platformListeners = prev }
}

// The status line may only blame 5900 when 5900 was actually tested and found busy. A
// remembered port is tried first, so we can land on 5903 with 5900 perfectly free — and
// telling the customer "port 5900 is already in use" would then be a cause we never observed.
func TestPickVncPortsDoesNotBlame5900WhenItWasNeverBusy(t *testing.T) {
	defer stubListeners(t, map[int]bool{})()

	vnc, _, defaultBusy := pickVncPorts(5907)
	if vnc != 5907 {
		t.Fatalf("did not reuse the remembered port: got %d", vnc)
	}
	if defaultBusy {
		t.Fatal("claimed 5900 was in use when nothing was listening on it")
	}
}

func TestPickVncPortsReportsTheDefaultBusyWhenItIs(t *testing.T) {
	defer stubListeners(t, map[int]bool{5900: true})()

	vnc, _, defaultBusy := pickVncPorts(0)
	if vnc != 5901 || !defaultBusy {
		t.Fatalf("got port %d defaultBusy=%v, want 5901 / true", vnc, defaultBusy)
	}
}
