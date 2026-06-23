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
//   - in development: an absolute http URL on localhost or 127.0.0.1 (any port)
//
// Everything else is rejected to prevent open-redirect attacks:
//   - protocol-relative URLs ("//evil.com")            — rejected: host present, no scheme
//   - backslash paths ("\\/evil.com")                  — rejected: browsers normalise \ to /
//   - non-http(s) schemes ("javascript:alert(1)")      — rejected: scheme check
//   - external domains ("https://evil.com")            — rejected: hostname check
//   - empty string                                     — rejected: nothing to redirect to
func isAllowedRedirect(next, environment string) bool {
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
	// Reject empty paths, double-slash paths ("//something" which browsers treat
	// as protocol-relative), and backslash paths ("\\/evil.com" which the WHATWG
	// URL standard normalises to "//evil.com" — a protocol-relative open redirect).
	if u.Host == "" {
		return u.Path != "" && !strings.HasPrefix(u.Path, "//") && !strings.HasPrefix(u.Path, "\\")
	}

	// Absolute URL: require http or https scheme.
	if u.Scheme != "http" && u.Scheme != "https" {
		return false
	}

	// Dev-environment: accept localhost origins (with or without port).
	// setCORSHeaders in remint.go applies the same isDevLocalhostURL check to
	// CORS origins, but additionally requires a non-empty port there.
	if environment == "development" && isDevLocalhostURL(u) {
		return true
	}

	// Hostname must be exactly "l42.eu" or end with ".l42.eu".
	// u.Hostname() strips the port, so "arachne.l42.eu:443" is handled correctly.
	host := u.Hostname()
	return host == "l42.eu" || strings.HasSuffix(host, ".l42.eu")
}

// isDevLocalhostURL reports whether a parsed URL is a local development origin:
// http scheme with host "localhost" or "127.0.0.1".
// Port is not checked here — callers may apply an additional port constraint.
// Specifically, setCORSHeaders in remint.go requires a non-empty port for CORS
// origins (browsers always include the port for non-default ports in the Origin
// header, so portless http://localhost is meaningless in that context).
func isDevLocalhostURL(u *url.URL) bool {
	if u.Scheme != "http" {
		return false
	}
	h := u.Hostname()
	return h == "localhost" || h == "127.0.0.1"
}
