package store

import (
	"errors"
	"testing"
)

// testKEK is a deterministic 32-byte key used in tests. Never use in production.
var testKEK = [32]byte{
	1, 2, 3, 4, 5, 6, 7, 8,
	9, 10, 11, 12, 13, 14, 15, 16,
	17, 18, 19, 20, 21, 22, 23, 24,
	25, 26, 27, 28, 29, 30, 31, 32,
}

// newTestStore opens an in-memory SQLite store for tests.
func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:", testKEK)
	if err != nil {
		t.Fatalf("Open(:memory:): %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// --- Principal tests ---

func TestCreatePrincipal_Human(t *testing.T) {
	s := newTestStore(t)
	p, err := s.CreatePrincipal(PrincipalClassHuman, "contact-abc-123")
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if p.ID == "" {
		t.Error("expected non-empty ID")
	}
	if p.Class != PrincipalClassHuman {
		t.Errorf("Class: got %q, want %q", p.Class, PrincipalClassHuman)
	}
	if p.ExternalID != "contact-abc-123" {
		t.Errorf("ExternalID: got %q, want %q", p.ExternalID, "contact-abc-123")
	}
	if p.CreatedAt.IsZero() {
		t.Error("CreatedAt should not be zero")
	}
}

func TestCreatePrincipal_Agent(t *testing.T) {
	s := newTestStore(t)
	p, err := s.CreatePrincipal(PrincipalClassAgent, "lucos-architect")
	if err != nil {
		t.Fatalf("CreatePrincipal: %v", err)
	}
	if p.Class != PrincipalClassAgent {
		t.Errorf("Class: got %q, want %q", p.Class, PrincipalClassAgent)
	}
	if p.ExternalID != "lucos-architect" {
		t.Errorf("ExternalID: got %q, want %q", p.ExternalID, "lucos-architect")
	}
}

func TestCreatePrincipal_Duplicate(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreatePrincipal(PrincipalClassHuman, "contact-dup"); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := s.CreatePrincipal(PrincipalClassHuman, "contact-dup")
	if !errors.Is(err, ErrDuplicate) {
		t.Errorf("duplicate: got %v, want ErrDuplicate", err)
	}
}

// Different classes may share the same external_id (contact-id and slug namespaces don't collide).
func TestCreatePrincipal_SameExternalIDDifferentClass(t *testing.T) {
	s := newTestStore(t)
	// Unlikely in practice, but the schema must allow it.
	if _, err := s.CreatePrincipal(PrincipalClassHuman, "shared-id"); err != nil {
		t.Fatalf("human create: %v", err)
	}
	if _, err := s.CreatePrincipal(PrincipalClassAgent, "shared-id"); err != nil {
		t.Fatalf("agent create with same externalID: %v", err)
	}
}

func TestGetPrincipalByID(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreatePrincipal(PrincipalClassHuman, "contact-xyz")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetPrincipalByID(created.ID)
	if err != nil {
		t.Fatalf("GetPrincipalByID: %v", err)
	}
	if got.ID != created.ID || got.Class != created.Class || got.ExternalID != created.ExternalID {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, created)
	}
}

func TestGetPrincipalByID_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetPrincipalByID("nonexistent-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestGetPrincipalByExternalID(t *testing.T) {
	s := newTestStore(t)
	created, err := s.CreatePrincipal(PrincipalClassAgent, "lucos-developer")
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	got, err := s.GetPrincipalByExternalID(PrincipalClassAgent, "lucos-developer")
	if err != nil {
		t.Fatalf("GetPrincipalByExternalID: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("ID mismatch: got %q, want %q", got.ID, created.ID)
	}
}

func TestGetPrincipalByExternalID_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetPrincipalByExternalID(PrincipalClassHuman, "contact-nobody")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// Lookup by ExternalID must be class-scoped: the same external_id in a different
// class must not match.
func TestGetPrincipalByExternalID_ClassScoped(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreatePrincipal(PrincipalClassHuman, "same-ext-id"); err != nil {
		t.Fatalf("create human: %v", err)
	}
	// Looking up the same string under the agent class must return ErrNotFound.
	_, err := s.GetPrincipalByExternalID(PrincipalClassAgent, "same-ext-id")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("expected ErrNotFound for agent with human external_id, got %v", err)
	}
}

func TestListPrincipals_All(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreatePrincipal(PrincipalClassHuman, "contact-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrincipal(PrincipalClassAgent, "lucos-ux"); err != nil {
		t.Fatal(err)
	}
	all, err := s.ListPrincipals()
	if err != nil {
		t.Fatalf("ListPrincipals: %v", err)
	}
	if len(all) != 2 {
		t.Errorf("want 2 principals, got %d", len(all))
	}
}

func TestListPrincipals_FilterByClass(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.CreatePrincipal(PrincipalClassHuman, "contact-2"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreatePrincipal(PrincipalClassAgent, "lucos-security"); err != nil {
		t.Fatal(err)
	}

	humans, err := s.ListPrincipals(PrincipalClassHuman)
	if err != nil {
		t.Fatalf("ListPrincipals(human): %v", err)
	}
	if len(humans) != 1 || humans[0].Class != PrincipalClassHuman {
		t.Errorf("want 1 human, got %v", humans)
	}

	agents, err := s.ListPrincipals(PrincipalClassAgent)
	if err != nil {
		t.Fatalf("ListPrincipals(agent): %v", err)
	}
	if len(agents) != 1 || agents[0].Class != PrincipalClassAgent {
		t.Errorf("want 1 agent, got %v", agents)
	}
}

func TestDeletePrincipal(t *testing.T) {
	s := newTestStore(t)
	p, err := s.CreatePrincipal(PrincipalClassHuman, "contact-to-delete")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePrincipal(p.ID); err != nil {
		t.Fatalf("DeletePrincipal: %v", err)
	}
	_, err = s.GetPrincipalByID(p.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestDeletePrincipal_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.DeletePrincipal("nonexistent")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// --- Credential tests ---

func TestCreateCredential_WebAuthn(t *testing.T) {
	s := newTestStore(t)
	p, err := s.CreatePrincipal(PrincipalClassHuman, "contact-webauthn")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte(`{"credentialId":"abc","publicKey":"..."}`)
	cred, err := s.CreateCredential(p.ID, CredentialTypeWebAuthn, data, "YubiKey 5 NFC")
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if cred.ID == "" {
		t.Error("expected non-empty credential ID")
	}
	if cred.PrincipalID != p.ID {
		t.Errorf("PrincipalID: got %q, want %q", cred.PrincipalID, p.ID)
	}
	if cred.Type != CredentialTypeWebAuthn {
		t.Errorf("Type: got %q, want %q", cred.Type, CredentialTypeWebAuthn)
	}
	if string(cred.Data) != string(data) {
		t.Errorf("Data mismatch: got %q, want %q", cred.Data, data)
	}
	if cred.Label != "YubiKey 5 NFC" {
		t.Errorf("Label: got %q, want %q", cred.Label, "YubiKey 5 NFC")
	}
}

func TestCreateCredential_MachineKey(t *testing.T) {
	s := newTestStore(t)
	p, err := s.CreatePrincipal(PrincipalClassAgent, "lucos-developer")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("public-key-material")
	cred, err := s.CreateCredential(p.ID, CredentialTypeMachineKey, data, "dev key")
	if err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if cred.Type != CredentialTypeMachineKey {
		t.Errorf("Type: got %q, want %q", cred.Type, CredentialTypeMachineKey)
	}
}

func TestCreateCredential_UnknownPrincipal(t *testing.T) {
	s := newTestStore(t)
	_, err := s.CreateCredential("does-not-exist", CredentialTypeWebAuthn, []byte("data"), "")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestGetCredential(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-getcred")
	data := []byte("raw-cred-data")
	created, err := s.CreateCredential(p.ID, CredentialTypeWebAuthn, data, "test key")
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.GetCredential(created.ID)
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	if got.ID != created.ID || got.PrincipalID != created.PrincipalID {
		t.Errorf("round-trip mismatch: got %+v, want %+v", got, created)
	}
	if string(got.Data) != string(data) {
		t.Errorf("Data mismatch: got %q, want %q", got.Data, data)
	}
}

func TestGetCredential_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetCredential("nonexistent-cred")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestListCredentialsByPrincipal(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-listcred")
	if _, err := s.CreateCredential(p.ID, CredentialTypeWebAuthn, []byte("key1"), "key one"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateCredential(p.ID, CredentialTypeWebAuthn, []byte("key2"), "key two"); err != nil {
		t.Fatal(err)
	}
	creds, err := s.ListCredentialsByPrincipal(p.ID)
	if err != nil {
		t.Fatalf("ListCredentialsByPrincipal: %v", err)
	}
	if len(creds) != 2 {
		t.Errorf("want 2 credentials, got %d", len(creds))
	}
}

func TestListCredentialsByPrincipal_Empty(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassAgent, "lucos-monitoring")
	creds, err := s.ListCredentialsByPrincipal(p.ID)
	if err != nil {
		t.Fatalf("ListCredentialsByPrincipal: %v", err)
	}
	if len(creds) != 0 {
		t.Errorf("want 0 credentials, got %d", len(creds))
	}
}

func TestDeleteCredential(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-delcred")
	cred, err := s.CreateCredential(p.ID, CredentialTypeWebAuthn, []byte("k"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteCredential(cred.ID); err != nil {
		t.Fatalf("DeleteCredential: %v", err)
	}
	_, err = s.GetCredential(cred.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("after delete: got %v, want ErrNotFound", err)
	}
}

func TestDeleteCredential_NotFound(t *testing.T) {
	s := newTestStore(t)
	err := s.DeleteCredential("nonexistent-cred")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

// Deleting a principal must cascade to its credentials.
func TestDeletePrincipal_CascadesToCredentials(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-cascade")
	cred, err := s.CreateCredential(p.ID, CredentialTypeWebAuthn, []byte("key"), "")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePrincipal(p.ID); err != nil {
		t.Fatalf("DeletePrincipal: %v", err)
	}
	_, err = s.GetCredential(cred.ID)
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("credential should have been cascade-deleted, got %v", err)
	}
}

// Ping verifies the DB liveness check works.
func TestPing(t *testing.T) {
	s := newTestStore(t)
	if err := s.Ping(); err != nil {
		t.Errorf("Ping: %v", err)
	}
}

// --- IdP session tests ---

func TestCreateAndGetIDPSession(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-idp-1")

	rawToken, sess, err := s.CreateIDPSession(p.ID)
	if err != nil {
		t.Fatalf("CreateIDPSession: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected non-empty rawToken")
	}
	if sess.PrincipalID != p.ID {
		t.Errorf("PrincipalID: got %q, want %q", sess.PrincipalID, p.ID)
	}
	if sess.ExpiresAt.IsZero() {
		t.Fatal("ExpiresAt should not be zero")
	}

	// GetIDPSessionByToken should return the same session.
	got, err := s.GetIDPSessionByToken(rawToken)
	if err != nil {
		t.Fatalf("GetIDPSessionByToken: %v", err)
	}
	if got.PrincipalID != p.ID {
		t.Errorf("PrincipalID: got %q, want %q", got.PrincipalID, p.ID)
	}
}

func TestGetIDPSessionByToken_NotFound(t *testing.T) {
	s := newTestStore(t)
	_, err := s.GetIDPSessionByToken("doesnotexist")
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("got %v, want ErrNotFound", err)
	}
}

func TestGetIDPSessionByToken_Revoked(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-idp-revoked")
	rawToken, _, err := s.CreateIDPSession(p.ID)
	if err != nil {
		t.Fatalf("CreateIDPSession: %v", err)
	}

	n, err := s.RevokeIDPSessionsForPrincipal(p.ID)
	if err != nil {
		t.Fatalf("RevokeIDPSessionsForPrincipal: %v", err)
	}
	if n != 1 {
		t.Errorf("revoked: got %d, want 1", n)
	}

	_, err = s.GetIDPSessionByToken(rawToken)
	if !errors.Is(err, ErrIDPSessionRevoked) {
		t.Errorf("got %v, want ErrIDPSessionRevoked", err)
	}
}

func TestRevokeIDPSessionsForPrincipal_NoSessions(t *testing.T) {
	s := newTestStore(t)
	p, _ := s.CreatePrincipal(PrincipalClassHuman, "contact-idp-nosess")
	n, err := s.RevokeIDPSessionsForPrincipal(p.ID)
	if err != nil {
		t.Fatalf("RevokeIDPSessionsForPrincipal: %v", err)
	}
	if n != 0 {
		t.Errorf("revoked: got %d, want 0", n)
	}
}

