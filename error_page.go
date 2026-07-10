package main

// Friendly, styled HTML error responses for aithne's own human-browser-facing
// entry points (lucas42/lucos_aithne#309). Before this, several reachable-
// but-erroring paths (missing/invalid /oauth2/authorize parameters, internal
// 5xxs) used raw http.Error() text responses — technically correct but an
// unstyled, technical-looking page for a real person to land on mid-login.
//
// Scope (per the lucos#260 reassessment lucas42 approved): this covers only
// requests aithne can still respond to — a full aithne crash-loop/total
// outage still yields a raw browser connection error, which is explicitly
// accepted (see #309's "explicitly out of scope"). This page therefore
// carries no inline/external script and needs no CSP nonce, so it has no
// dependency beyond the already-static aithne.css/favicon.svg files.
//
// Not used for OAuth2/OIDC protocol JSON endpoints (/oauth2/token,
// /oauth2/userinfo) or for the WebAuthn ceremony JSON endpoints already
// wrapped with friendly copy client-side in login.html/enrol.html's own JS
// (/auth/login/begin|finish, /enrol/begin|finish) — those are consumed
// programmatically, not rendered directly to a browser.

import (
	"html/template"
	"net/http"
)

var errorPageTmpl = template.Must(template.ParseFS(templateFS, "templates/error.html"))

// errorPageData holds the per-request data injected into templates/error.html.
type errorPageData struct {
	Title   string
	Message string
	// RetryGuidance is a short, explicit signal about whether retrying will
	// help, appended as its own sentence — see
	// ~/.claude/agent-memory/lucos-ux/copy_error_retry_guidance.md. Never
	// leave the user guessing whether a refresh will fix it.
	RetryGuidance string
}

// Reusable retry-guidance sentences (see copy_error_retry_guidance.md):
//   - retryTransient: for downstream/internal failures where a retry may
//     genuinely succeed a moment later.
//   - retryUnlikely: for configuration errors (unknown/misconfigured OIDC
//     client, unregistered redirect_uri) where retrying the same request
//     changes nothing — only the administrator can fix it.
const (
	retryTransient = "Try again in a moment."
	// No "if this continues" — a config error isn't transient or a matter of
	// degree, it's broken now (lucos-ux review on #309).
	retryUnlikely = "Retrying won't help. Contact the administrator for help."
)

// renderErrorPage serves a friendly, styled HTML error page in place of a raw
// http.Error() text response.
func renderErrorPage(w http.ResponseWriter, statusCode int, title, message, retryGuidance string) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; frame-ancestors 'none'")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(statusCode)
	// Errors from Execute here can only be a broken template (a build-time
	// bug, not a runtime condition) — nothing further to do at request time.
	_ = errorPageTmpl.Execute(w, errorPageData{Title: title, Message: message, RetryGuidance: retryGuidance})
}
