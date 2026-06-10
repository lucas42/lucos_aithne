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

func TestRotateSigningKeyIfOlderThan_RotatesWhenOld(t *testing.T) {
	s := newTestStore(t)

	original, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}

	// A zero (or negative) maxAge means "always rotate" — any key is older than 0.
	rotated, newKey, err := s.RotateSigningKeyIfOlderThan(0)
	if err != nil {
		t.Fatalf("RotateSigningKeyIfOlderThan(0): %v", err)
	}
	if !rotated {
		t.Error("expected rotation when maxAge=0")
	}
	if newKey == nil {
		t.Fatal("expected non-nil newKey on rotation")
	}
	if newKey.ID == original.ID {
		t.Error("expected a different key ID after rotation")
	}
	if newKey.Status != "active" {
		t.Errorf("newKey.Status: got %q, want active", newKey.Status)
	}
}

func TestRotateSigningKeyIfOlderThan_NoopWhenRecent(t *testing.T) {
	s := newTestStore(t)

	original, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}

	// A very large maxAge means the freshly-created key is well within the window.
	rotated, newKey, err := s.RotateSigningKeyIfOlderThan(365 * 24 * time.Hour)
	if err != nil {
		t.Fatalf("RotateSigningKeyIfOlderThan(365d): %v", err)
	}
	if rotated {
		t.Error("expected no rotation for a fresh key within the window")
	}
	if newKey != nil {
		t.Error("expected nil newKey when no rotation occurred")
	}

	// Active key must still be the original.
	current, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey after no-op: %v", err)
	}
	if current.ID != original.ID {
		t.Errorf("active key changed despite no rotation: got %q, want %q", current.ID, original.ID)
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
