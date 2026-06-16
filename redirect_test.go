package main

import "testing"

func TestIsAllowedRedirect(t *testing.T) {
	cases := []struct {
		name  string
		input string
		want  bool
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
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isAllowedRedirect(tc.input)
			if got != tc.want {
				t.Errorf("isAllowedRedirect(%q) = %v; want %v", tc.input, got, tc.want)
			}
		})
	}
}
