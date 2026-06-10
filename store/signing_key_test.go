package store

import (
	"crypto/x509"
	"testing"
	"time"
)

func TestGetOrCreateActiveSigningKey_CreatesOnFirstCall(t *testing.T) {
	s := newTestStore(t)

	k, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}
	if k.ID == "" {
		t.Error("expected non-empty ID")
	}
	if k.Algorithm != "ES256" {
		t.Errorf("Algorithm: got %q, want ES256", k.Algorithm)
	}
	if len(k.PrivateKey) == 0 {
		t.Error("expected non-empty PrivateKey DER")
	}
	if k.Status != "active" {
		t.Errorf("Status: got %q, want active", k.Status)
	}
	if k.RetiredAt != nil {
		t.Error("expected RetiredAt to be nil for active key")
	}
	// Verify the DER is a valid PKCS8 EC private key.
	if _, err := x509.ParsePKCS8PrivateKey(k.PrivateKey); err != nil {
		t.Errorf("private key DER is not valid PKCS8: %v", err)
	}
}

func TestGetOrCreateActiveSigningKey_ReturnsSameKey(t *testing.T) {
	s := newTestStore(t)

	k1, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("first call: %v", err)
	}
	k2, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if k1.ID != k2.ID {
		t.Errorf("expected same key ID on repeated calls, got %q and %q", k1.ID, k2.ID)
	}
}

func TestRotateSigningKey(t *testing.T) {
	s := newTestStore(t)

	original, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}

	newKey, err := s.RotateSigningKey()
	if err != nil {
		t.Fatalf("RotateSigningKey: %v", err)
	}
	if newKey.ID == original.ID {
		t.Error("expected a different key after rotation")
	}
	if newKey.Status != "active" {
		t.Errorf("new key status: got %q, want active", newKey.Status)
	}

	// Original key must now be retired.
	keys, err := s.ListVerificationKeys(24 * time.Hour)
	if err != nil {
		t.Fatalf("ListVerificationKeys: %v", err)
	}
	var foundOriginal, foundNew bool
	for _, k := range keys {
		switch k.ID {
		case original.ID:
			foundOriginal = true
			if k.Status != "retired" {
				t.Errorf("original key status: got %q, want retired", k.Status)
			}
			if k.RetiredAt == nil {
				t.Error("retired key should have RetiredAt set")
			}
		case newKey.ID:
			foundNew = true
			if k.Status != "active" {
				t.Errorf("new key status: got %q, want active", k.Status)
			}
		}
	}
	if !foundOriginal {
		t.Error("original key not found in verification keys")
	}
	if !foundNew {
		t.Error("new key not found in verification keys")
	}
}

func TestListVerificationKeys_ExcludesExpiredRetired(t *testing.T) {
	s := newTestStore(t)

	// Create an active key, rotate to retire it.
	_, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}
	_, err = s.RotateSigningKey()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// A negative window moves the cutoff into the future, so no recently-retired key
	// can satisfy retired_at >= future_cutoff. Only the active key should be returned.
	keys, err := s.ListVerificationKeys(-1 * time.Second)
	if err != nil {
		t.Fatalf("ListVerificationKeys(-1s): %v", err)
	}
	for _, k := range keys {
		if k.Status == "retired" {
			t.Errorf("future cutoff: unexpected retired key %q", k.ID)
		}
	}
}
