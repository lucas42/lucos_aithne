package main

// ratelimit.go — per-key fixed-window rate limiter for authentication endpoints.
//
// Implements a concurrent-safe keyedLimiter used to rate-limit:
//   - POST /oauth2/token  by client_id  (tokenEndpointLimit   req/window)
//   - POST /auth/login/begin by IP      (ceremonyBeginLimit   req/window)
//   - POST /enrol/begin        by IP    (same ceremonyLimiter instance)
//   - GET  /admin/grants/check by calling principal (grantsCheckLimit req/window)
//
// Design choices (per lucos-security comment on #160):
//   - Fixed-window (not sliding-window or token-bucket). The precision difference
//     is immaterial for this threat model — we're defending against automated runs,
//     not timing attacks.
//   - stdlib only — no external dependencies added.
//   - Per-key cleanup runs on a ticker so the map does not grow unboundedly.
//
// IP extraction:
//   clientIP() trusts X-Real-IP (set unconditionally by lucos_router/nginx,
//   overwrites any client-supplied value) and falls back to r.RemoteAddr.
//   Direct-port access to aithne is blocked by lucos_firewall on avalon (port 8039
//   is not in the public-ports allow-list), so X-Real-IP is trustworthy in practice
//   — the risk originally noted in the design has been verified as mitigated.

import (
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	// tokenEndpointLimit: max client_credentials attempts per client_id per minute.
	// A legitimate agent re-auths at most once per 15-min JWT TTL; 60/min is a very
	// wide margin while blocking credential-stuffing runs.
	tokenEndpointLimit  = 60
	tokenEndpointWindow = time.Minute

	// ceremonyBeginLimit: max /auth/login/begin or /enrol/begin calls per IP per minute.
	// A human performs at most one ceremony at a time; 10/min is generous.
	ceremonyBeginLimit  = 10
	ceremonyBeginWindow = time.Minute

	// grantsCheckLimit: max /admin/grants/check calls per calling principal per
	// minute. principal_id and scope are both practically enumerable, and this
	// route accepts the narrow aithne:read scope, so it's rate-limited to raise
	// the cost of walking the full grants table one boolean at a time
	// (lucos_aithne#305). Keyed on the calling principal (from the verified
	// token's sub), not IP — this is an authenticated admin route, so principal
	// identity is the meaningful dimension. 60/min matches tokenEndpointLimit's
	// precedent: a wide margin for legitimate bulk-verification workflows,
	// still blocks naive automation.
	grantsCheckLimit  = 60
	grantsCheckWindow = time.Minute

	// rateLimiterCleanupInterval: how often stale key entries are evicted from the
	// limiter maps. Chosen to be much longer than the window so entries get a chance
	// to contribute across multiple requests before being swept.
	rateLimiterCleanupInterval = 5 * time.Minute
)

// windowEntry holds the request count and the start of the current window for a
// single rate-limit key.
type windowEntry struct {
	count       int
	windowStart time.Time
}

// keyedLimiter is a per-key fixed-window rate limiter. Concurrent-safe.
type keyedLimiter struct {
	mu      sync.Mutex
	entries map[string]*windowEntry
	limit   int
	window  time.Duration
}

// newKeyedLimiter creates a rate limiter that allows up to limit requests per
// window per key.
func newKeyedLimiter(limit int, window time.Duration) *keyedLimiter {
	return &keyedLimiter{
		entries: make(map[string]*windowEntry),
		limit:   limit,
		window:  window,
	}
}

// Allow returns true if the key is within its rate limit for the current window,
// false if the limit has been exceeded. The counter is always incremented so
// repeated calls accumulate correctly within the window.
// The current count (after increment) is also returned for logging.
func (rl *keyedLimiter) Allow(key string) (bool, int) {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	now := time.Now()
	e, ok := rl.entries[key]
	if !ok || now.Sub(e.windowStart) > rl.window {
		rl.entries[key] = &windowEntry{count: 1, windowStart: now}
		return true, 1
	}
	e.count++
	return e.count <= rl.limit, e.count
}

// sweepExpired removes entries whose window has long expired to prevent unbounded
// map growth. Entries within the current window are left intact.
func (rl *keyedLimiter) sweepExpired() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-rl.window)
	for k, e := range rl.entries {
		if e.windowStart.Before(cutoff) {
			delete(rl.entries, k)
		}
	}
}

// clientIP extracts the real client IP from the request.
// Trusts X-Real-IP (set unconditionally by lucos_router/nginx on every request,
// overwriting any client-supplied value) when present; falls back to r.RemoteAddr.
//
// Note: direct external access to the aithne service port (8039) is blocked by
// lucos_firewall on avalon, so only the router can reach aithne from outside the
// host. X-Real-IP is therefore trustworthy — a client cannot spoof it through the
// router. (Verified by lucos-security against configy public-ports, issue #160.)
func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
