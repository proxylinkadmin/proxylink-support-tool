package main

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
