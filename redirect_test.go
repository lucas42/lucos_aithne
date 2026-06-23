package main

import "testing"

func TestIsAllowedRedirect(t *testing.T) {
	cases := []struct {
		name        string
		input       string
		environment string // "" behaves like "production" (dev check is == "development" only)
		want        bool
	}{
		// Safe: bare paths (same-origin)
		{name: "root path", input: "/", want: true},
		{name: "bare path", input: "/admin/grants", want: true},
		{name: "path with query", input: "/explore?q=foo", want: true},

		// Safe: in-estate absolute URLs
		{name: "arachne subdomain", input: "https://arachne.l42.eu/explore", want: true},
		{name: "aithne subdomain", input: "https://aithne.l42.eu/admin", want: true},
		{name: "l42.eu root", input: "https://l42.eu/", want: true},
		{name: "http scheme in-estate", input: "http://arachne.l42.eu/foo", want: true},

		// Unsafe: empty
		{name: "empty string", input: "", want: false},

		// Unsafe: protocol-relative
		{name: "protocol-relative", input: "//evil.com/path", want: false},
		{name: "protocol-relative l42.eu", input: "//l42.eu/path", want: false},

		// Unsafe: non-http(s) schemes
		{name: "javascript scheme", input: "javascript:alert(1)", want: false},
		{name: "data scheme", input: "data:text/html,<h1>hi</h1>", want: false},
		{name: "ftp scheme", input: "ftp://l42.eu/file", want: false},

		// Unsafe: external domains
		{name: "external domain", input: "https://evil.com/path", want: false},
		{name: "l42.eu suffix spoofing", input: "https://notl42.eu/path", want: false},
		{name: "suffix craft attack", input: "https://evil.l42.eu.attacker.com/", want: false},

		// Unsafe: double-slash path (browser-parsed as protocol-relative)
		{name: "double-slash path", input: "//evil.com", want: false},

		// Unsafe: backslash paths — WHATWG URL normalises \ to /, so "\\/evil.com"
		// would be interpreted as "//evil.com" (a protocol-relative open redirect).
		{name: "backslash path", input: "\\evil.com", want: false},
		{name: "backslash-slash path", input: "\\/evil.com", want: false},

		// Edge cases explicitly considered — not open-redirect attacks but
		// documented here to show the behaviour was thought through:
		//
		// Embedded credential: url.Parse puts "evil.com" in the User field and
		// "l42.eu" in Host, so Hostname() returns "l42.eu". Destination is
		// in-estate. Modern browsers also block or warn on credential-in-URL
		// navigation, so this is not exploitable.
		{name: "embedded credential in-estate host", input: "https://evil.com@l42.eu/", want: true},
		// Relative path without leading slash: parsed as a bare path with no host.
		// The browser resolves it relative to aithne.l42.eu so the user stays
		// in-estate. Malformed but not an open redirect.
		{name: "relative path no leading slash", input: "evil.com/path", want: true},

		// Dev-environment: localhost origins accepted (any port, or no port).
		{name: "dev localhost with port", input: "http://localhost:3000/path", environment: "development", want: true},
		{name: "dev localhost no port", input: "http://localhost/path", environment: "development", want: true},
		{name: "dev 127.0.0.1 with port", input: "http://127.0.0.1:8080/", environment: "development", want: true},
		{name: "dev 127.0.0.1 no port", input: "http://127.0.0.1/", environment: "development", want: true},
		// Dev-environment: https://localhost is NOT accepted (dev doesn't use TLS).
		{name: "dev https localhost rejected", input: "https://localhost:3000/path", environment: "development", want: false},
		// Dev-environment: localhost is rejected in production.
		{name: "dev localhost in prod", input: "http://localhost:3000/path", environment: "production", want: false},
		{name: "dev localhost in prod empty env", input: "http://localhost:3000/path", environment: "", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedRedirect(tc.input, tc.environment)
			if got != tc.want {
				t.Errorf("isAllowedRedirect(%q, %q) = %v; want %v", tc.input, tc.environment, got, tc.want)
			}
		})
	}
}
