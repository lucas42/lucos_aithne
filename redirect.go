package main

import (
	"net/url"
	"strings"
)

// isAllowedRedirect reports whether next is a safe post-login redirect target.
//
// A URL is safe when it is:
//   - a bare path (no host, so same-origin by definition), e.g. "/admin/grants"
//   - an absolute http(s) URL whose hostname is "l42.eu" or a "*.l42.eu" subdomain
//
// Everything else is rejected to prevent open-redirect attacks:
//   - protocol-relative URLs ("//evil.com")       — rejected: host present, no scheme
//   - non-http(s) schemes ("javascript:alert(1)") — rejected: scheme check
//   - external domains ("https://evil.com")       — rejected: hostname check
//   - empty string                                — rejected: nothing to redirect to
func isAllowedRedirect(next string) bool {
	if next == "" {
		return false
	}
	u, err := url.Parse(next)
	if err != nil {
		return false
	}

	// Protocol-relative URL: has a host but no scheme ("//evil.com/path").
	// url.Parse("//evil.com/path") → {Scheme:"", Host:"evil.com", Path:"/path"}
	if u.Scheme == "" && u.Host != "" {
		return false
	}

	// Bare path — same-origin, always safe.
	// Reject empty paths and double-slash paths ("//something" which browsers treat
	// as protocol-relative).
	if u.Host == "" {
		return u.Path != "" && !strings.HasPrefix(u.Path, "//")
	}

	// Absolute URL: require http or https scheme.
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Hostname must be exactly "l42.eu" or end with ".l42.eu".
	// u.Hostname() strips the port, so "arachne.l42.eu:443" is handled correctly.
	host := u.Hostname()
	return host == "l42.eu" || strings.HasSuffix(host, ".l42.eu")
}
