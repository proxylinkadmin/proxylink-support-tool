// Port selection for the VNC server.
//
// Deliberately in its own file with NO build constraint: main.go is //go:build windows, so
// anything living there cannot be tested anywhere but Windows. This logic is the part worth
// testing and it is platform-neutral, so it goes where `go test` can actually reach it.

package main

import (
	"fmt"
	"net"
)

// portFree reports whether we can bind this TCP port right now.
//
// ⚠️ This is a point-in-time answer, not a reservation — something else can take the port
// between here and winvnc starting. That is why the caller VERIFIES afterwards (see
// vncPortIsOurs) instead of trusting this. Judge it by what it produced, not by what it said.
func portFree(port int) bool {
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
func pickVncPorts(preferred int) (vncPort, httpPort int) {
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
		if portFree(p) && portFree(p-100) {
			return p, p - 100
		}
	}
	// Nothing free in range. Return the default and let the verification step fail loudly
	// rather than reporting a port we have no reason to believe in.
	return 5900, 5800
}
