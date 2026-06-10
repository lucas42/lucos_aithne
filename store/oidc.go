// Package store — OIDC client and authorization-code management.
//
// Per ADR-0001 §1, lucos_aithne is a full OpenID Provider from day one.
// This file implements the persistence layer for:
//   - oidc_clients: registered relying parties (client_id + hashed secret + redirect_uris)
//   - oidc_auth_codes: single-use authorization codes issued by /oauth2/authorize
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// Sentinel errors for OIDC operations.
var (
	// ErrInvalidRedirectURI is returned when the redirect_uri is not registered for the client.
	ErrInvalidRedirectURI = errors.New("store: redirect_uri not registered for this client")

	// ErrAuthCodeExpired is returned when an authorization code has passed its expiry.
	ErrAuthCodeExpired = errors.New("store: authorization code has expired")

	// ErrAuthCodeUsed is returned when an authorization code has already been consumed.
	ErrAuthCodeUsed = errors.New("store: authorization code has already been used")
)

// OIDCClient represents a registered OIDC relying party.
type OIDCClient struct {
	ID           string    // client_id (human-readable slug, e.g. "myapp")
	SecretHash   string    // hex-encoded SHA-256 of the raw client secret
	RedirectURIs []string  // allowed redirect URIs
	ClientName   string
	CreatedAt    time.Time
}

// HasRedirectURI reports whether uri is registered for this client.
// Comparison is exact (no path wildcards, no trailing-slash normalisation).
func (c *OIDCClient) HasRedirectURI(uri string) bool {
	for _, r := range c.RedirectURIs {
		if r == uri {
			return true
		}
	}
	return false
}

// OIDCAuthCode is a single-use authorization code issued by the authorization endpoint.
type OIDCAuthCode struct {
	CodeHash    string     // hex-encoded SHA-256 of the raw code
	ClientID    string
	PrincipalID string
	RedirectURI string
	Scope       string     // space-separated scope list as supplied in the authorization request
	Nonce       string     // forwarded from the authorization request; embedded in the ID token
	ExpiresAt   time.Time
	CreatedAt   time.Time
	UsedAt      *time.Time
}

// CreateOIDCClient registers a new OIDC relying party.
// clientID must be unique; returns ErrDuplicate if already registered.
// secretHash is hex-encoded SHA-256 of the raw secret; the caller must return
// the raw secret to the admin and must never persist it.
func (s *Store) CreateOIDCClient(clientID, secretHash, clientName string, redirectURIs []string) (*OIDCClient, error) {
	redirectJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return nil, fmt.Errorf("store: marshal redirect_uris: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO oidc_clients (id, secret_hash, redirect_uris, client_name, created_at)
		 VALUES (?, ?, ?, ?, ?)`,
		clientID, secretHash, string(redirectJSON), clientName, now.Format(time.RFC3339),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("store: create oidc client: %w", err)
	}
	return &OIDCClient{
		ID:           clientID,
		SecretHash:   secretHash,
		RedirectURIs: redirectURIs,
		ClientName:   clientName,
		CreatedAt:    now,
	}, nil
}

// GetOIDCClient returns the OIDC client with the given ID.
// Returns ErrNotFound if no such client exists.
func (s *Store) GetOIDCClient(clientID string) (*OIDCClient, error) {
	row := s.db.QueryRow(
		`SELECT id, secret_hash, redirect_uris, client_name, created_at
		 FROM oidc_clients WHERE id = ?`,
		clientID,
	)
	return scanOIDCClient(row)
}

// ListOIDCClients returns all registered OIDC clients ordered by creation time.
func (s *Store) ListOIDCClients() ([]*OIDCClient, error) {
	rows, err := s.db.Query(
		`SELECT id, secret_hash, redirect_uris, client_name, created_at
		 FROM oidc_clients ORDER BY created_at`,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list oidc clients: %w", err)
	}
	defer rows.Close()
	var result []*OIDCClient
	for rows.Next() {
		c, err := scanOIDCClientRow(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate oidc clients: %w", err)
	}
	return result, nil
}

// DeleteOIDCClient removes a registered OIDC client.
// Returns ErrNotFound if no such client exists.
func (s *Store) DeleteOIDCClient(clientID string) error {
	res, err := s.db.Exec(`DELETE FROM oidc_clients WHERE id = ?`, clientID)
	if err != nil {
		return fmt.Errorf("store: delete oidc client: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete oidc client rows-affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// CreateOIDCAuthCode stores a new authorization code.
// rawCode is the code returned to the client; only SHA-256(rawCode) is stored.
// expiresAt should be a short TTL (5 minutes is typical).
func (s *Store) CreateOIDCAuthCode(rawCode, clientID, principalID, redirectURI, scope, nonce string, expiresAt time.Time) error {
	codeHash := HashToken(rawCode)
	now := time.Now().UTC()
	_, err := s.db.Exec(
		`INSERT INTO oidc_auth_codes
		 (code_hash, client_id, principal_id, redirect_uri, scope, nonce, expires_at, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		codeHash, clientID, principalID, redirectURI, scope, nonce,
		expiresAt.Format(time.RFC3339),
		now.Format(time.RFC3339),
	)
	if err != nil {
		return fmt.Errorf("store: create oidc auth code: %w", err)
	}
	return nil
}

// ConsumeOIDCAuthCode atomically looks up and marks the authorization code as used.
// Returns ErrNotFound if the code hash is unknown.
// Returns ErrAuthCodeExpired if the code has passed its expiry.
// Returns ErrAuthCodeUsed if the code has already been consumed.
// On success, returns the stored auth code details for use in token minting.
func (s *Store) ConsumeOIDCAuthCode(rawCode string) (*OIDCAuthCode, error) {
	codeHash := HashToken(rawCode)

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck

	row := tx.QueryRow(
		`SELECT code_hash, client_id, principal_id, redirect_uri, scope, nonce,
		        expires_at, created_at, used_at
		 FROM oidc_auth_codes WHERE code_hash = ?`,
		codeHash,
	)
	var ac OIDCAuthCode
	var expiresAtStr, createdAtStr string
	var usedAtStr *string
	if err := row.Scan(
		&ac.CodeHash, &ac.ClientID, &ac.PrincipalID, &ac.RedirectURI,
		&ac.Scope, &ac.Nonce, &expiresAtStr, &createdAtStr, &usedAtStr,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan auth code: %w", err)
	}

	expTime, err := parseTime(expiresAtStr)
	if err != nil {
		return nil, fmt.Errorf("store: parse auth code expires_at: %w", err)
	}
	ac.ExpiresAt = expTime

	createdTime, err := parseTime(createdAtStr)
	if err != nil {
		return nil, fmt.Errorf("store: parse auth code created_at: %w", err)
	}
	ac.CreatedAt = createdTime

	if usedAtStr != nil {
		return nil, ErrAuthCodeUsed
	}
	if time.Now().After(expTime) {
		return nil, ErrAuthCodeExpired
	}

	now := time.Now().UTC().Format(time.RFC3339)
	res, err := tx.Exec(
		`UPDATE oidc_auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL`,
		now, codeHash,
	)
	if err != nil {
		return nil, fmt.Errorf("store: consume auth code update: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		// Another request consumed it between our SELECT and UPDATE.
		return nil, ErrAuthCodeUsed
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit consume auth code: %w", err)
	}
	return &ac, nil
}

// GenerateRawCode returns a cryptographically random 32-byte hex string suitable
// for use as an authorization code. The raw value is returned to the client; only
// SHA-256(raw) is stored.
func GenerateRawCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("store: generate random code: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// --- Internal scan helpers ---

func scanOIDCClient(row *sql.Row) (*OIDCClient, error) {
	var c OIDCClient
	var redirectJSON, createdAt string
	if err := row.Scan(&c.ID, &c.SecretHash, &redirectJSON, &c.ClientName, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan oidc client: %w", err)
	}
	if err := json.Unmarshal([]byte(redirectJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("store: unmarshal redirect_uris: %w", err)
	}
	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse oidc client created_at: %w", err)
	}
	c.CreatedAt = t
	return &c, nil
}

func scanOIDCClientRow(rows *sql.Rows) (*OIDCClient, error) {
	var c OIDCClient
	var redirectJSON, createdAt string
	if err := rows.Scan(&c.ID, &c.SecretHash, &redirectJSON, &c.ClientName, &createdAt); err != nil {
		return nil, fmt.Errorf("store: scan oidc client row: %w", err)
	}
	if err := json.Unmarshal([]byte(redirectJSON), &c.RedirectURIs); err != nil {
		return nil, fmt.Errorf("store: unmarshal redirect_uris: %w", err)
	}
	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse oidc client created_at: %w", err)
	}
	c.CreatedAt = t
	return &c, nil
}
