// Package store implements aithne's principal registry and credential store.
//
// Per ADR-0001 §4, aithne mints no identities of its own — every principal
// references an external identity authority, and aithne owns only the credential:
//   - human  principals: ExternalID is a lucos_contacts contact-id.
//   - agent  principals: ExternalID is a lucos_agent personas.json slug.
//
// Non-AI service principals are not supported day-one; they stay on
// lucos_creds linkedCredentials. If migrated, their identity would be a
// lucos_configy system code — never a minted aithne ID.
package store

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite" // registers the "sqlite" driver
)

// PrincipalClass classifies the type of an authenticated principal.
type PrincipalClass string

const (
	// PrincipalClassHuman is a human user authenticated via WebAuthn passkey.
	// ExternalID is a lucos_contacts contact-id.
	PrincipalClassHuman PrincipalClass = "human"

	// PrincipalClassAgent is an AI agent authenticated via OAuth2 client-credentials.
	// ExternalID is the lucos_agent personas.json slug (e.g. "lucos-architect").
	// Slugs must remain stable; they are recorded at provisioning time and not
	// re-validated at runtime (personas.json is not a runtime/build dependency).
	PrincipalClassAgent PrincipalClass = "agent"
)

// CredentialType identifies the kind of credential bound to a principal.
type CredentialType string

const (
	// CredentialTypeWebAuthn is a WebAuthn public-key credential (human principals).
	// Data carries JSON-encoded credential data (public key COSE, sign count, AAGUID, …).
	CredentialTypeWebAuthn CredentialType = "webauthn"

	// CredentialTypeMachineKey is a long-lived machine key (agent principals).
	// The key lives in lucos_creds and is exchanged at runtime for a short-lived
	// session — it is never stored there. Data carries the public key material
	// (format finalised by the client-credentials ticket).
	CredentialTypeMachineKey CredentialType = "machine_key"
)

// Principal is a registry entry binding a principal class to an external identity.
type Principal struct {
	ID         string         // aithne-internal UUID v4
	Class      PrincipalClass // "human" or "agent"
	ExternalID string         // contact-id (human) or personas slug (agent)
	CreatedAt  time.Time
}

// Credential is verifiable key material bound to a principal.
// The format of Data is credential-type-specific (see CredentialType constants).
type Credential struct {
	ID          string
	PrincipalID string
	Type        CredentialType
	Data        []byte
	Label       string
	CreatedAt   time.Time
}

// Sentinel errors returned by Store methods.
var (
	// ErrNotFound is returned when a queried entity does not exist.
	ErrNotFound = errors.New("store: not found")

	// ErrDuplicate is returned when (class, external_id) is already registered.
	ErrDuplicate = errors.New("store: duplicate principal (class + external_id must be unique)")
)

// Store manages aithne's principal registry and credential store via SQLite.
type Store struct {
	db *sql.DB
}

// Open opens (or creates) the SQLite database at path and applies schema migrations.
// Pass ":memory:" for an ephemeral in-memory database (tests only).
func Open(path string) (*Store, error) {
	dsn := buildDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	// A single connection ensures per-connection PRAGMAs (foreign_keys) are
	// reliable, and is appropriate for an embedded SQLite database.
	db.SetMaxOpenConns(1)

	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate: %w", err)
	}
	return s, nil
}

// Close releases the underlying database connection.
func (s *Store) Close() error { return s.db.Close() }

// Ping verifies the database is reachable.
func (s *Store) Ping() error { return s.db.Ping() }

// buildDSN appends required pragmas to the DSN.
func buildDSN(path string) string {
	pragma := "_pragma=foreign_keys(ON)"
	if strings.Contains(path, "?") {
		return path + "&" + pragma
	}
	return path + "?" + pragma
}

func (s *Store) migrate() error {
	stmts := []string{
		`PRAGMA foreign_keys = ON`,
		`CREATE TABLE IF NOT EXISTS principals (
			id          TEXT PRIMARY KEY,
			class       TEXT NOT NULL CHECK(class IN ('human', 'agent')),
			external_id TEXT NOT NULL,
			created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			UNIQUE(class, external_id)
		)`,
		`CREATE TABLE IF NOT EXISTS credentials (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
			type         TEXT NOT NULL CHECK(type IN ('webauthn', 'machine_key')),
			data         BLOB NOT NULL,
			label        TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		// signing_keys stores EC P-256 private keys used to sign session JWTs.
		// The id is used as the JWK "kid" header so verifiers can look up the
		// correct public key from the JWKS endpoint.
		`CREATE TABLE IF NOT EXISTS signing_keys (
			id          TEXT PRIMARY KEY,
			status      TEXT NOT NULL CHECK(status IN ('active', 'retired')),
			algorithm   TEXT NOT NULL,
			private_key BLOB NOT NULL,
			created_at  DATETIME NOT NULL DEFAULT (datetime('now')),
			retired_at  DATETIME
		)`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			summary := stmt
			if len(summary) > 40 {
				summary = summary[:40] + "…"
			}
			return fmt.Errorf("exec %q: %w", summary, err)
		}
	}
	return nil
}

// --- Principal registry ---

// CreatePrincipal adds a new principal to the registry.
// Returns ErrDuplicate if (class, externalID) is already registered.
func (s *Store) CreatePrincipal(class PrincipalClass, externalID string) (*Principal, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("store: generate id: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO principals (id, class, external_id, created_at) VALUES (?, ?, ?, ?)`,
		id, string(class), externalID, now.Format(time.RFC3339),
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("store: create principal: %w", err)
	}
	return &Principal{ID: id, Class: class, ExternalID: externalID, CreatedAt: now}, nil
}

// GetPrincipalByID returns the principal with the given internal ID.
// Returns ErrNotFound if no such principal exists.
func (s *Store) GetPrincipalByID(id string) (*Principal, error) {
	row := s.db.QueryRow(
		`SELECT id, class, external_id, created_at FROM principals WHERE id = ?`, id,
	)
	return scanPrincipal(row)
}

// GetPrincipalByExternalID looks up a principal by (class, externalID).
// Returns ErrNotFound if no such principal exists.
func (s *Store) GetPrincipalByExternalID(class PrincipalClass, externalID string) (*Principal, error) {
	row := s.db.QueryRow(
		`SELECT id, class, external_id, created_at FROM principals WHERE class = ? AND external_id = ?`,
		string(class), externalID,
	)
	return scanPrincipal(row)
}

// ListPrincipals returns all principals, optionally filtered by class.
// Passing no classes returns all principals ordered by creation time.
func (s *Store) ListPrincipals(classes ...PrincipalClass) ([]*Principal, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if len(classes) == 0 {
		rows, err = s.db.Query(
			`SELECT id, class, external_id, created_at FROM principals ORDER BY created_at`,
		)
	} else {
		args := make([]any, len(classes))
		placeholders := make([]string, len(classes))
		for i, c := range classes {
			args[i] = string(c)
			placeholders[i] = "?"
		}
		q := `SELECT id, class, external_id, created_at FROM principals WHERE class IN (` +
			strings.Join(placeholders, ",") + `) ORDER BY created_at`
		rows, err = s.db.Query(q, args...)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list principals: %w", err)
	}
	defer rows.Close()
	return collectPrincipals(rows)
}

// DeletePrincipal removes a principal and all its credentials (via ON DELETE CASCADE).
// Returns ErrNotFound if no such principal exists.
func (s *Store) DeletePrincipal(id string) error {
	res, err := s.db.Exec(`DELETE FROM principals WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete principal: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete principal rows-affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Credential store ---

// CreateCredential adds a new credential bound to an existing principal.
// Returns ErrNotFound if principalID does not reference a known principal.
func (s *Store) CreateCredential(principalID string, credType CredentialType, data []byte, label string) (*Credential, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("store: generate id: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO credentials (id, principal_id, type, data, label, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, principalID, string(credType), data, label, now.Format(time.RFC3339),
	)
	if err != nil {
		if isFKViolation(err) {
			return nil, ErrNotFound // principal doesn't exist
		}
		return nil, fmt.Errorf("store: create credential: %w", err)
	}
	return &Credential{
		ID:          id,
		PrincipalID: principalID,
		Type:        credType,
		Data:        data,
		Label:       label,
		CreatedAt:   now,
	}, nil
}

// GetCredential returns the credential with the given ID.
// Returns ErrNotFound if no such credential exists.
func (s *Store) GetCredential(id string) (*Credential, error) {
	row := s.db.QueryRow(
		`SELECT id, principal_id, type, data, label, created_at FROM credentials WHERE id = ?`, id,
	)
	return scanCredential(row)
}

// ListCredentialsByPrincipal returns all credentials for the given principal,
// ordered by creation time.
func (s *Store) ListCredentialsByPrincipal(principalID string) ([]*Credential, error) {
	rows, err := s.db.Query(
		`SELECT id, principal_id, type, data, label, created_at FROM credentials WHERE principal_id = ? ORDER BY created_at`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	defer rows.Close()
	return collectCredentials(rows)
}

// DeleteCredential removes a single credential by ID.
// Returns ErrNotFound if no such credential exists.
func (s *Store) DeleteCredential(id string) error {
	res, err := s.db.Exec(`DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("store: delete credential: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: delete credential rows-affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Internal helpers ---

func scanPrincipal(row *sql.Row) (*Principal, error) {
	p := &Principal{}
	var createdAt string
	if err := row.Scan(&p.ID, (*string)(&p.Class), &p.ExternalID, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan principal: %w", err)
	}
	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse principal timestamp: %w", err)
	}
	p.CreatedAt = t
	return p, nil
}

func collectPrincipals(rows *sql.Rows) ([]*Principal, error) {
	var result []*Principal
	for rows.Next() {
		p := &Principal{}
		var createdAt string
		if err := rows.Scan(&p.ID, (*string)(&p.Class), &p.ExternalID, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan principal row: %w", err)
		}
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse principal timestamp: %w", err)
		}
		p.CreatedAt = t
		result = append(result, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate principals: %w", err)
	}
	return result, nil
}

func scanCredential(row *sql.Row) (*Credential, error) {
	c := &Credential{}
	var createdAt string
	if err := row.Scan(&c.ID, &c.PrincipalID, (*string)(&c.Type), &c.Data, &c.Label, &createdAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan credential: %w", err)
	}
	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse credential timestamp: %w", err)
	}
	c.CreatedAt = t
	return c, nil
}

func collectCredentials(rows *sql.Rows) ([]*Credential, error) {
	var result []*Credential
	for rows.Next() {
		c := &Credential{}
		var createdAt string
		if err := rows.Scan(&c.ID, &c.PrincipalID, (*string)(&c.Type), &c.Data, &c.Label, &createdAt); err != nil {
			return nil, fmt.Errorf("store: scan credential row: %w", err)
		}
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse credential timestamp: %w", err)
		}
		c.CreatedAt = t
		result = append(result, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate credentials: %w", err)
	}
	return result, nil
}

// parseTime handles both RFC3339 and the plain "2006-01-02 15:04:05" format
// that SQLite may return for DATETIME columns.
func parseTime(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	return time.Parse("2006-01-02 15:04:05", s)
}

// newID returns a new random UUID v4.
func newID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // RFC 4122 variant
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// isUniqueViolation reports whether err is a SQLite UNIQUE constraint error.
func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "UNIQUE constraint") || strings.Contains(msg, "constraint failed: principals.class, principals.external_id")
}

// isFKViolation reports whether err is a SQLite FOREIGN KEY constraint error.
func isFKViolation(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "FOREIGN KEY constraint")
}
