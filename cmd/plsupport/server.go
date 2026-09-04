// Deliberately NOT behind the windows build tag. allowedServer is the single check standing
// between a telephone scammer and a signed binary that will believe whatever their server
// says, so it is kept as a pure function that can be tested on any machine. See server_test.go.

package main

import (
	"net/url"
	"strings"
)

// The only hosts -server= may name. See allowedServer.
var serverHosts = []string{"app.proxylink.dev", "proxylink.dev"}

// allowedServer accepts only ProxyLink's own hosts over HTTPS. Anything else is ignored and
// the build-time default stands, so a bad flag degrades to the correct server rather than
// to a chosen one.
//
// ⚠️ An exact list, not a *.proxylink.dev suffix. A suffix match is only as strong as our
// control of every name in the zone, and one dangling CNAME to a deprovisioned service would
// hand an attacker the whole trust story back: their server would supply the name in the
// consent dialog, the tunnel endpoint and the VNC password, with our signed binary vouching
// for all of it. The flag exists for our own testing, so the cost of listing hosts by hand
// is a line of code and the cost of getting it wrong is the customer's screen.
func allowedServer(raw string) (string, bool) {
	raw = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(raw), "/"))
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Path != "" ||
		u.RawQuery != "" || u.Fragment != "" || u.Port() != "" {
		return "", false
	}
	host := strings.ToLower(strings.TrimSuffix(u.Hostname(), "."))
	for _, allowed := range serverHosts {
		if host == allowed {
			return "https://" + host, true
		}
	}
	return "", false
}
