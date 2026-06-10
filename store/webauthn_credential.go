// Package store — WebAuthn credential serialisation helpers.
//
// WebAuthn credentials are stored as JSON BLOBs in the credentials table.
// This file defines the canonical on-disk format and the helpers to convert
// between it and the webauthn library's Credential type.
package store

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// ErrInvalidCredentialData is returned when the credential BLOB is missing
// required fields or cannot be parsed.
var ErrInvalidCredentialData = errors.New("store: invalid WebAuthn credential data")

// WebAuthnCredentialData is the JSON structure stored in credentials.data for
// CredentialTypeWebAuthn rows. All []byte fields are base64-encoded by the
// standard library's JSON encoder.
type WebAuthnCredentialData struct {
	CredentialID []byte   `json:"credential_id"`
	PublicKey    []byte   `json:"public_key"`
	SignCount    uint32   `json:"sign_count"`
	AAGUID       []byte   `json:"aaguid"`
	// Transports carries the authenticator's reported transport hints (usb, nfc,
	// ble, internal, etc.) and is optional — absent for legacy registrations.
	Transports []string `json:"transports,omitempty"`
}

// MarshalWebAuthnCredential serialises a webauthn.Credential into the store
// BLOB format and validates that all required fields are present.
// Returns ErrInvalidCredentialData if the credential is structurally incomplete.
func MarshalWebAuthnCredential(c *webauthn.Credential) ([]byte, error) {
	if len(c.ID) == 0 {
		return nil, fmt.Errorf("%w: credential_id is empty", ErrInvalidCredentialData)
	}
	if len(c.PublicKey) == 0 {
		return nil, fmt.Errorf("%w: public_key is empty", ErrInvalidCredentialData)
	}
	if len(c.Authenticator.AAGUID) == 0 {
		return nil, fmt.Errorf("%w: aaguid is empty", ErrInvalidCredentialData)
	}

	var transports []string
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}

	d := WebAuthnCredentialData{
		CredentialID: c.ID,
		PublicKey:    c.PublicKey,
		SignCount:    c.Authenticator.SignCount,
		AAGUID:       c.Authenticator.AAGUID,
		Transports:   transports,
	}
	return json.Marshal(d)
}

// UnmarshalWebAuthnCredential parses a credential BLOB into a webauthn.Credential.
// Returns ErrInvalidCredentialData if required fields are absent or unparseable.
func UnmarshalWebAuthnCredential(data []byte) (*webauthn.Credential, error) {
	var d WebAuthnCredentialData
	if err := json.Unmarshal(data, &d); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidCredentialData, err)
	}
	if len(d.CredentialID) == 0 {
		return nil, fmt.Errorf("%w: credential_id missing", ErrInvalidCredentialData)
	}
	if len(d.PublicKey) == 0 {
		return nil, fmt.Errorf("%w: public_key missing", ErrInvalidCredentialData)
	}
	if len(d.AAGUID) == 0 {
		return nil, fmt.Errorf("%w: aaguid missing", ErrInvalidCredentialData)
	}

	c := &webauthn.Credential{
		ID:        d.CredentialID,
		PublicKey: d.PublicKey,
		Authenticator: webauthn.Authenticator{
			AAGUID:    d.AAGUID,
			SignCount: d.SignCount,
		},
	}
	for _, t := range d.Transports {
		c.Transport = append(c.Transport, protocol.AuthenticatorTransport(t))
	}
	return c, nil
}
