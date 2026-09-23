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
	vnc, http := pickVncPorts(0)
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

	vnc, http := pickVncPorts(0)
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
	vnc, _ := pickVncPorts(5907)
	if vnc != 5907 {
		t.Fatalf("did not prefer the remembered port: got %d, want 5907", vnc)
	}
}
