package store

import (
	"testing"

	"github.com/go-webauthn/webauthn/webauthn"
)

// testCredential builds a minimal webauthn.Credential for round-trip tests.
func testCredential(backupEligible, backupState bool) *webauthn.Credential {
	return &webauthn.Credential{
		ID:        []byte("test-credential-id"),
		PublicKey: []byte("test-public-key-bytes"),
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("test-aaguid-16b!"),
			SignCount: 42,
		},
		Flags: webauthn.CredentialFlags{
			BackupEligible: backupEligible,
			BackupState:    backupState,
		},
	}
}

// TestMarshalUnmarshal_RoundTrip verifies that all fields survive a
// marshal → unmarshal cycle.
func TestMarshalUnmarshal_RoundTrip(t *testing.T) {
	cases := []struct {
		name           string
		backupEligible bool
		backupState    bool
	}{
		{"not backup eligible", false, false},
		{"backup eligible not backed up", true, false},
		{"backup eligible and backed up", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orig := testCredential(tc.backupEligible, tc.backupState)

			data, err := MarshalWebAuthnCredential(orig)
			if err != nil {
				t.Fatalf("MarshalWebAuthnCredential: %v", err)
			}

			got, err := UnmarshalWebAuthnCredential(data)
			if err != nil {
				t.Fatalf("UnmarshalWebAuthnCredential: %v", err)
			}

			if got.Flags.BackupEligible != tc.backupEligible {
				t.Errorf("BackupEligible: got %v, want %v", got.Flags.BackupEligible, tc.backupEligible)
			}
			if got.Flags.BackupState != tc.backupState {
				t.Errorf("BackupState: got %v, want %v", got.Flags.BackupState, tc.backupState)
			}
			if got.Authenticator.SignCount != orig.Authenticator.SignCount {
				t.Errorf("SignCount: got %d, want %d", got.Authenticator.SignCount, orig.Authenticator.SignCount)
			}
			if string(got.ID) != string(orig.ID) {
				t.Errorf("ID: got %q, want %q", got.ID, orig.ID)
			}
		})
	}
}

// TestMarshalWebAuthnCredential_RejectsEmpty verifies validation errors on
// incomplete credentials.
func TestMarshalWebAuthnCredential_RejectsEmpty(t *testing.T) {
	cases := []struct {
		name string
		c    *webauthn.Credential
	}{
		{"empty credential_id", &webauthn.Credential{
			PublicKey:     []byte("pk"),
			Authenticator: webauthn.Authenticator{AAGUID: []byte("aag")},
		}},
		{"empty public_key", &webauthn.Credential{
			ID:            []byte("id"),
			Authenticator: webauthn.Authenticator{AAGUID: []byte("aag")},
		}},
		{"empty aaguid", &webauthn.Credential{
			ID:        []byte("id"),
			PublicKey: []byte("pk"),
		}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := MarshalWebAuthnCredential(tc.c)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}
