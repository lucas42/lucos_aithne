package store

import (
	"errors"
	"testing"
)

func testVocab() *Vocabulary {
	return NewVocabulary([]string{"aithne:admin", "render-ui", "photos:read"})
}

func TestCreateGrant_Basic(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")

	g, err := s.CreateGrant(p.ID, "aithne:admin", "development", "contact-admin", testVocab())
	if err != nil {
		t.Fatalf("CreateGrant: %v", err)
	}
	if g.ID == "" {
		t.Error("expected non-empty grant ID")
	}
	if g.Scope != "aithne:admin" {
		t.Errorf("Scope: got %q, want aithne:admin", g.Scope)
	}
	if g.Environment != "development" {
		t.Errorf("Environment: got %q, want development", g.Environment)
	}
	if g.GrantedBy != "contact-admin" {
		t.Errorf("GrantedBy: got %q, want contact-admin", g.GrantedBy)
	}
	if g.RevokedAt != nil {
		t.Error("new grant should not be revoked")
	}
	if !g.IsActive() {
		t.Error("new grant should be active")
	}
}

func TestCreateGrant_UnknownScope(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")

	_, err := s.CreateGrant(p.ID, "nonexistent:scope", "development", "admin", testVocab())
	if !errors.Is(err, ErrUnknownScope) {
		t.Errorf("expected ErrUnknownScope, got %v", err)
	}
}

func TestCreateGrant_UnknownPrincipal(t *testing.T) {
	s := newTestStore(t)

	_, err := s.CreateGrant("nonexistent-id", "aithne:admin", "development", "admin", testVocab())
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestCreateGrant_DuplicateActive(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")

	_, err := s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	if err != nil {
		t.Fatalf("first CreateGrant: %v", err)
	}
	_, err = s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("expected ErrDuplicate on duplicate active grant, got %v", err)
	}
}

func TestCreateGrant_ReGrantAfterRevoke(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")

	g, _ := s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	if err := s.RevokeGrant(g.ID, "admin"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}
	// Should be possible to re-grant the same (principal, scope, env) after revocation.
	_, err := s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	if err != nil {
		t.Errorf("re-grant after revoke: expected nil, got %v", err)
	}
}

func TestRevokeGrant(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	g, _ := s.CreateGrant(p.ID, "aithne:admin", "development", "granter", testVocab())

	if err := s.RevokeGrant(g.ID, "revoker"); err != nil {
		t.Fatalf("RevokeGrant: %v", err)
	}

	// Fetch and verify revocation state.
	fetched, err := s.GetGrant(g.ID)
	if err != nil {
		t.Fatalf("GetGrant after revoke: %v", err)
	}
	if fetched.IsActive() {
		t.Error("revoked grant should not be active")
	}
	if fetched.RevokedBy == nil || *fetched.RevokedBy != "revoker" {
		t.Errorf("RevokedBy: got %v, want 'revoker'", fetched.RevokedBy)
	}
	if fetched.RevokedAt == nil {
		t.Error("RevokedAt should be set")
	}
}

func TestRevokeGrant_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.RevokeGrant("nonexistent-id", "admin")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound, got %v", err)
	}
}

func TestRevokeGrant_AlreadyRevoked(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	g, _ := s.CreateGrant(p.ID, "aithne:admin", "development", "granter", testVocab())

	s.RevokeGrant(g.ID, "revoker")
	err := s.RevokeGrant(g.ID, "revoker2")
	if !errors.Is(err, ErrGrantRevoked) {
		t.Errorf("expected ErrGrantRevoked, got %v", err)
	}
}

func TestListGrants_ActiveOnly(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	g1, _ := s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	g2, _ := s.CreateGrant(p.ID, "render-ui", "development", "admin", testVocab())
	s.RevokeGrant(g2.ID, "admin")

	grants, err := s.ListGrants(p.ID, "development", true)
	if err != nil {
		t.Fatalf("ListGrants: %v", err)
	}
	if len(grants) != 1 {
		t.Fatalf("expected 1 active grant, got %d", len(grants))
	}
	if grants[0].ID != g1.ID {
		t.Errorf("unexpected grant: got %q, want %q", grants[0].ID, g1.ID)
	}
}

func TestListGrants_IncludeRevoked(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	_, _ = s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	g2, _ := s.CreateGrant(p.ID, "render-ui", "development", "admin", testVocab())
	s.RevokeGrant(g2.ID, "admin")

	grants, err := s.ListGrants(p.ID, "development", false)
	if err != nil {
		t.Fatalf("ListGrants (all): %v", err)
	}
	if len(grants) != 2 {
		t.Errorf("expected 2 grants (active+revoked), got %d", len(grants))
	}
}

func TestListGrants_EnvironmentFilter(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	s.CreateGrant(p.ID, "aithne:admin", "production", "admin", testVocab())

	devGrants, _ := s.ListGrants(p.ID, "development", true)
	if len(devGrants) != 1 {
		t.Errorf("development grants: expected 1, got %d", len(devGrants))
	}

	prodGrants, _ := s.ListGrants(p.ID, "production", true)
	if len(prodGrants) != 1 {
		t.Errorf("production grants: expected 1, got %d", len(prodGrants))
	}
}

func TestGetActiveScopes(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())
	s.CreateGrant(p.ID, "render-ui", "development", "admin", testVocab())

	scopes, err := s.GetActiveScopes(p.ID, "development")
	if err != nil {
		t.Fatalf("GetActiveScopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected 2 scopes, got %d: %v", len(scopes), scopes)
	}
}

func TestGetActiveScopes_Empty(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")

	scopes, err := s.GetActiveScopes(p.ID, "development")
	if err != nil {
		t.Fatalf("GetActiveScopes: %v", err)
	}
	if len(scopes) != 0 {
		t.Errorf("expected empty scopes for new principal, got %v", scopes)
	}
}

func TestDeletePrincipal_CascadesToGrants(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-abc")
	g, _ := s.CreateGrant(p.ID, "aithne:admin", "development", "admin", testVocab())

	if err := s.DeletePrincipal(p.ID); err != nil {
		t.Fatalf("DeletePrincipal: %v", err)
	}
	_, err := s.GetGrant(g.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for grant after principal delete, got %v", err)
	}
}

// --- Vocabulary tests ---

func TestVocabulary_Contains(t *testing.T) {
	v := testVocab()
	if !v.Contains("aithne:admin") {
		t.Error("aithne:admin should be in vocabulary")
	}
	if !v.Contains("render-ui") {
		t.Error("render-ui should be in vocabulary")
	}
	if v.Contains("nonexistent") {
		t.Error("nonexistent should not be in vocabulary")
	}
	if v.Contains("") {
		t.Error("empty string should not be in vocabulary")
	}
}
