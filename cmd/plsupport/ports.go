// Port selection for the VNC server.
//
// Deliberately in its own file with NO build constraint: main.go is //go:build windows, so
// anything living there cannot be tested anywhere but Windows. This logic is the part worth
// testing and it is platform-neutral, so it goes where `go test` can actually reach it.

package main

import (
	"fmt"
	"net"
	"time"
)

// platformListeners returns the TCP ports the OS says are being listened on, or nil when we
// cannot ask. Set from main.go on Windows; nil elsewhere (and in tests, which set it directly).
var platformListeners func() map[int]bool

// portFree reports whether this TCP port looks genuinely unused.
//
// ⚠️ It asks THREE questions, because the obvious one is the wrong one. A plain
// net.Listen("127.0.0.1:N") answers "can I bind this?", and on Windows that is NOT the same as
// "is anything serving here?": a process holding 0.0.0.0:N without SO_EXCLUSIVEADDRUSE leaves
// the more specific 127.0.0.1:N bindable, so the bind succeeds and the port looks free. That
// is exactly how we handed 5900 to winvnc on a machine where TightVNC was already serving it
// (2026-09-23) — the probe was confident and wrong. So:
//
//  1. does the OS list a listener on it?   (authoritative, Windows only)
//  2. does anything ANSWER a connection?   (catches a server we cannot see in the table)
//  3. can we actually bind it?             (catches a reservation with nothing serving yet)
//
// Still a point-in-time answer, not a reservation — something can take the port between here
// and winvnc starting. That is why the caller VERIFIES afterwards (vncPortIsOurs) instead of
// trusting this. Judge it by what it produced, not by what it said.
func portFree(port int) bool {
	return portFreeWith(port, nil)
}

func portFreeWith(port int, listening map[int]bool) bool {
	if listening != nil && listening[port] {
		return false
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 400*time.Millisecond); err == nil {
		c.Close()
		return false
	}
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// pickVncPorts chooses a free (VNC, HTTP) pair.
//
// 5900 is the default and stays the first choice, so nothing changes on the overwhelming
// majority of machines. When another VNC server already holds it — TightVNC, RealVNC, or an
// MSP's own UltraVNC — we step AROUND it rather than taking the port: CLAUDE.md is explicit
// that a service predating us is the customer's, and TightVNC in particular we have never
// deployed and never touch.
//
// The HTTP port moves with it. UltraVNC's Java viewer defaults to 5800, and the very machine
// that collides on 5900 is a good bet to collide on 5800 as well; a winvnc that cannot bind
// its HTTP port is a needless way to lose the session.
// defaultBusy reports whether 5900 itself was unavailable, and exists so the message shown to
// the customer can only say "5900 is in use" when we actually looked. A remembered port is
// tried FIRST, so we can land on 5903 without ever testing 5900 — asserting a cause we never
// observed is how a status line ends up lying to the person reading it.
func pickVncPorts(preferred int) (vncPort, httpPort int, defaultBusy bool) {
	// One snapshot of the listener table for the whole scan — 20 PowerShell round trips while
	// the user watches a "Preparing screen sharing" spinner is not worth the precision.
	var listening map[int]bool
	if platformListeners != nil {
		listening = platformListeners()
	}

	defaultBusy = !(portFreeWith(5900, listening) && portFreeWith(5800, listening))

	candidates := make([]int, 0, 21)
	if preferred >= 5900 && preferred <= 5919 {
		candidates = append(candidates, preferred) // a restart reuses what the server was told
	}
	for p := 5900; p <= 5919; p++ {
		if p != preferred {
			candidates = append(candidates, p)
		}
	}
	for _, p := range candidates {
		if portFreeWith(p, listening) && portFreeWith(p-100, listening) {
			return p, p - 100, defaultBusy
		}
	}
	// Nothing free in range. Return the default and let the verification step fail loudly
	// rather than reporting a port we have no reason to believe in.
	return 5900, 5800, defaultBusy
}
