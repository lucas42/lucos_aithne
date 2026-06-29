// template_scripts_test.go — CI guard for inline <script> syntax in Go templates.
//
// Background: the #211 regression introduced U+2018/U+2019 smart-quote characters
// as JS string delimiters in templates/admin_grants.html, a SyntaxError that would
// have broken the grants-admin page on deploy. It passed CI because nothing in Go's
// test suite ever parses the template output as JS — html/template validates escaping,
// not JS syntax. This file closes that gap.
//
// Approach (per the #214 architectural assessment):
//   - Render each template with representative stub data through the real engine,
//     so Go template actions ({{.Foo | js}} etc.) are correctly substituted.
//   - Extract inline <script> blocks using an HTML parser (skipping external scripts).
//   - Parse each extracted script with a Go JS parser (github.com/tdewolff/parse/v2/js).
//   - Fail the test if any script has a syntax error.
//
// This is the systemic fix — it catches the full class (not just smart quotes),
// stays Go-native (no new CI job), and also smoke-tests that every template
// executes without panicking on representative data.

package main

import (
	"bytes"
	"html/template"
	"io"
	"strings"
	"testing"

	goparse "github.com/tdewolff/parse/v2"
	"github.com/tdewolff/parse/v2/js"
	"golang.org/x/net/html"
)

// extractInlineScripts parses the HTML in r and returns the text content of
// every <script> element that has no src attribute (i.e. inline scripts only).
// External scripts are skipped — they contain no inline JS to check and their
// src paths are not local files we can read.
func extractInlineScripts(r io.Reader) ([]string, error) {
	doc, err := html.Parse(r)
	if err != nil {
		return nil, err
	}
	var scripts []string
	var walk func(*html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "script" {
			// Skip external scripts (<script src="...">).
			hasSrc := false
			for _, a := range n.Attr {
				if a.Key == "src" {
					hasSrc = true
					break
				}
			}
			if !hasSrc {
				var buf strings.Builder
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					if c.Type == html.TextNode {
						buf.WriteString(c.Data)
					}
				}
				if src := strings.TrimSpace(buf.String()); src != "" {
					scripts = append(scripts, src)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)
	return scripts, nil
}

// checkJSSyntax parses src as JavaScript and returns any syntax error.
// Uses tdewolff/parse v2, which would have caught the #211 smart-quote regression
// (U+2018/U+2019 as string delimiters produce a parse error).
func checkJSSyntax(src string) error {
	_, err := js.Parse(goparse.NewInputString(src), js.Options{})
	return err
}

// TestTemplateScriptsSyntax renders each Go template with representative stub
// data, extracts inline <script> blocks, and verifies each parses as valid JS.
//
// This is the regression guard for the #211/#214 incident class: a JS syntax
// error introduced into an inline template script must be caught here before it
// can reach main.
func TestTemplateScriptsSyntax(t *testing.T) {
	const nonce = "testnonce"

	tests := []struct {
		name string
		tmpl string
		data any
	}{
		{
			name: "login.html",
			tmpl: "templates/login.html",
			data: loginPageData{Nonce: nonce},
		},
		{
			name: "enrol.html",
			tmpl: "templates/enrol.html",
			data: enrolPageData{
				Nonce:       nonce,
				Token:       "test-invite-token",
				ContactID:   "42",
				DisplayName: "Alice Example",
			},
		},
		{
			name: "enrol_error.html",
			tmpl: "templates/enrol_error.html",
			data: enrolErrorPageData{Nonce: nonce, Reason: "not_found"},
		},
		{
			name: "admin_enrol.html",
			tmpl: "templates/admin_enrol.html",
			data: adminEnrolPageData{Nonce: nonce, SessionToken: "test.jwt.token"},
		},
		{
			name: "admin_grants.html",
			// The template that contained the #211 smart-quote regression.
			tmpl: "templates/admin_grants.html",
			data: adminGrantsPageData{
				Nonce:        nonce,
				SessionToken: "test.jwt.token",
				ScopeStatuses: []scopeStatusData{
					{Scope: "arachne:read", Granted: true, GrantID: "grant-abc"},
					{Scope: "aithne:admin", Granted: false},
				},
			},
		},
		{
			name: "admin_agents.html",
			tmpl: "templates/admin_agents.html",
			data: adminAgentsPageData{
				Nonce:        nonce,
				SessionToken: "test.jwt.token",
				ScopeStatuses: []scopeStatusData{
					{Scope: "arachne:read", Granted: true, GrantID: "grant-abc"},
					{Scope: "aithne:admin", Granted: false},
				},
			},
		},
		{
			name: "index.html",
			tmpl: "templates/index.html",
			data: homePageData{Nonce: nonce, LoggedIn: true, DisplayName: "Alice"},
		},
		{
			name: "privacy.html",
			tmpl: "templates/privacy.html",
			data: privacyPageData{Nonce: nonce},
		},
		{
			name: "access_denied.html",
			tmpl: "templates/access_denied.html",
			data: accessDeniedPageData{Nonce: nonce},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Parse and render the template with the real engine and real templateFS
			// (the same embed.FS the production handlers use). This ensures template
			// actions are substituted correctly before JS extraction.
			tmpl := template.Must(template.ParseFS(templateFS, tt.tmpl))
			var buf bytes.Buffer
			if err := tmpl.Execute(&buf, tt.data); err != nil {
				t.Fatalf("render %s: %v", tt.tmpl, err)
			}

			// Extract inline <script> blocks from the rendered HTML.
			scripts, err := extractInlineScripts(&buf)
			if err != nil {
				t.Fatalf("extract scripts from %s: %v", tt.tmpl, err)
			}

			// Check each inline script for JS syntax errors.
			for i, script := range scripts {
				if err := checkJSSyntax(script); err != nil {
					t.Errorf("%s: inline script %d/%d has a JS syntax error: %v\n--- script content ---\n%s\n--- end ---",
						tt.tmpl, i+1, len(scripts), err, script)
				}
			}

			// Log the script count as a sanity check that extraction is working.
			// If a template with known inline scripts suddenly reports 0, extraction
			// has regressed (e.g. all scripts gained src= attributes).
			t.Logf("%s: %d inline script(s) checked", tt.tmpl, len(scripts))
		})
	}
}

// TestGrantsPickerTypeCoercion guards against the #224 regression class:
// /admin/human-principals emits contact_id as a JSON string ("788") while
// /admin/contacts emits id as a JSON number (788). Set.prototype.has uses
// strict identity (SameValueZero), so without String() coercion on both
// sides every has() call returns false and the datalist renders empty —
// making name→ID resolution silently fail for every contact.
//
// This test renders admin_grants.html, extracts its inline script, and asserts
// that both String() coercions are present. It cannot execute the JS (the
// Go test suite has no runtime for that), but it provides a content guard:
// if either coercion is removed, the test fails before the regression ships.
func TestGrantsPickerTypeCoercion(t *testing.T) {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/admin_grants.html"))
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, adminGrantsPageData{
		Nonce:        "testnonce",
		SessionToken: "test.jwt.token",
		ScopeStatuses: []scopeStatusData{
			{Scope: "aithne:admin", Granted: false},
		},
	}); err != nil {
		t.Fatalf("render admin_grants.html: %v", err)
	}

	scripts, err := extractInlineScripts(&buf)
	if err != nil {
		t.Fatalf("extract scripts: %v", err)
	}
	if len(scripts) == 0 {
		t.Fatal("no inline scripts found in admin_grants.html — extraction broken")
	}

	combined := strings.Join(scripts, "\n")

	// Both sides of the Set.has() comparison must be coerced to string.
	// principal contact_id comes from the API as a JSON string; contact id
	// comes as a JSON number — without these two coercions the filter always
	// produces an empty result.
	if !strings.Contains(combined, "String(p.contact_id)") {
		t.Error("admin_grants.html: missing String(p.contact_id) coercion when building principalContactIds Set — contact_id type mismatch will break the picker")
	}
	if !strings.Contains(combined, "String(c.id)") {
		t.Error("admin_grants.html: missing String(c.id) coercion in allContacts.filter() — contact id type mismatch will break the picker")
	}
}
