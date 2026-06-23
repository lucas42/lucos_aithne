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
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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
	RevokedBy   *string    // non-nil if revoked (mirrors Grant.RevokedBy)
	RevokedAt   *time.Time // non-nil if revoked (mirrors Grant.RevokedAt)
}

// IsActive reports whether the credential has not been revoked.
func (c *Credential) IsActive() bool { return c.RevokedAt == nil }

// Sentinel errors returned by Store methods.
var (
	// ErrNotFound is returned when a queried entity does not exist.
	ErrNotFound = errors.New("store: not found")

	// ErrDuplicate is returned when (class, external_id) is already registered.
	ErrDuplicate = errors.New("store: duplicate principal (class + external_id must be unique)")

	// ErrInviteExpired is returned when the invite token has passed its expires_at.
	ErrInviteExpired = errors.New("store: enrolment invite has expired")

	// ErrInviteUsed is returned when the invite token has already been consumed.
	ErrInviteUsed = errors.New("store: enrolment invite has already been used")

	// ErrCredentialRevoked is returned when attempting to revoke an already-revoked credential.
	ErrCredentialRevoked = errors.New("store: credential is already revoked")

	// ErrIDPSessionExpired is returned when an IdP session has passed its expires_at.
	ErrIDPSessionExpired = errors.New("store: IdP session has expired")

	// ErrIDPSessionRevoked is returned when an IdP session has been explicitly revoked.
	ErrIDPSessionRevoked = errors.New("store: IdP session has been revoked")
)

// IDPSession is a long-lived server-side session established at WebAuthn login
// per ADR-0003 §1. It is the credential gating the silent re-mint endpoint.
// Raw tokens are never stored; only SHA-256(rawToken) is persisted.
type IDPSession struct {
	TokenHash   string
	PrincipalID string
	CreatedAt   time.Time
	ExpiresAt   time.Time
	RevokedAt   *time.Time
}

// IsValid reports whether the session is neither expired nor revoked.
func (s *IDPSession) IsValid() bool {
	return s.RevokedAt == nil && s.ExpiresAt.After(time.Now())
}

// Store manages aithne's principal registry and credential store via SQLite.
type Store struct {
	db  *sql.DB
	kek [32]byte // Key-Encryption Key for AES-256-GCM envelope encryption of signing key material.
}

// Open opens (or creates) the SQLite database at path and applies schema migrations.
// kek is the 32-byte Key-Encryption Key used to AES-256-GCM encrypt signing key material at rest.
// Pass ":memory:" for an ephemeral in-memory database (tests only).
func Open(path string, kek [32]byte) (*Store, error) {
	dsn := buildDSN(path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %q: %w", path, err)
	}
	// A single connection ensures per-connection PRAGMAs (foreign_keys) are
	// reliable, and is appropriate for an embedded SQLite database.
	db.SetMaxOpenConns(1)

	s := &Store{db: db, kek: kek}
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
		// grants is the default-deny scope-grant store per ADR-0001 §6.
		// A row means "principal_id has scope in environment". No row = no access.
		// Revocation sets revoked_by/revoked_at; revoked rows are kept for audit.
		`CREATE TABLE IF NOT EXISTS grants (
			id           TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
			scope        TEXT NOT NULL,
			environment  TEXT NOT NULL,
			granted_by   TEXT NOT NULL,
			granted_at   DATETIME NOT NULL DEFAULT (datetime('now')),
			revoked_by   TEXT,
			revoked_at   DATETIME
		)`,
		// Partial unique index: prevents duplicate *active* grants.
		// Revoked rows (revoked_at IS NOT NULL) are excluded so a revoked grant
		// can be re-granted.
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_grants_active
		 ON grants(principal_id, scope, environment) WHERE revoked_at IS NULL`,
		// enrolment_invites stores admin-issued single-use tokens that authorise
		// a passkey registration ceremony for a specific contact.
		// token_hash is SHA-256(rawToken) hex — the raw token is never stored,
		// only returned to the admin at creation time. This limits exposure if the
		// SQLite file is ever read by an unauthorised party.
		`CREATE TABLE IF NOT EXISTS enrolment_invites (
			token_hash  TEXT PRIMARY KEY,
			contact_id  TEXT NOT NULL,
			created_by  TEXT NOT NULL,
			created_at  DATETIME NOT NULL,
			expires_at  DATETIME NOT NULL,
			used_at     DATETIME
		)`,
		// oidc_clients stores registered OIDC relying parties per ADR-0001 §1.
		// client_id is a human-readable slug chosen by the admin at registration.
		// secret_hash is SHA-256(rawSecret) hex; the raw secret is returned once
		// at registration and never persisted.
		// redirect_uris is a JSON array of allowed redirect URIs.
		`CREATE TABLE IF NOT EXISTS oidc_clients (
			id            TEXT PRIMARY KEY,
			secret_hash   TEXT NOT NULL,
			redirect_uris TEXT NOT NULL,
			client_name   TEXT NOT NULL DEFAULT '',
			created_at    DATETIME NOT NULL DEFAULT (datetime('now'))
		)`,
		// oidc_auth_codes stores single-use authorization codes issued by the
		// authorization endpoint. The raw code is returned to the client; only
		// SHA-256(rawCode) is stored here. Codes expire after 5 minutes and are
		// consumed (used_at set) on first use — any replay returns ErrAuthCodeUsed.
		`CREATE TABLE IF NOT EXISTS oidc_auth_codes (
			code_hash    TEXT PRIMARY KEY,
			client_id    TEXT NOT NULL,
			principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
			redirect_uri TEXT NOT NULL,
			scope        TEXT NOT NULL DEFAULT '',
			nonce        TEXT NOT NULL DEFAULT '',
			expires_at   DATETIME NOT NULL,
			created_at   DATETIME NOT NULL DEFAULT (datetime('now')),
			used_at      DATETIME
		)`,
		// idp_sessions stores long-lived IdP session tokens per ADR-0003 §1.
		// The raw token is returned to the principal as a cookie at WebAuthn login;
		// only SHA-256(rawToken) is stored here. IdP sessions outlive the short-lived
		// aithne_session access token (15 min) and are the revocation control for
		// the silent re-mint endpoint: revoking an IdP session prevents further
		// re-mints by that principal.
		`CREATE TABLE IF NOT EXISTS idp_sessions (
			token_hash   TEXT PRIMARY KEY,
			principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
			created_at   DATETIME NOT NULL,
			expires_at   DATETIME NOT NULL,
			revoked_at   DATETIME
		)`,
		// Index to speed up RevokeIDPSessionsForPrincipal (bulk revoke by principal).
		`CREATE INDEX IF NOT EXISTS idx_idp_sessions_principal
		 ON idp_sessions(principal_id)`,
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

	// Additive migrations: ALTER TABLE ADD COLUMN (nullable, so no default needed).
	// addColumnIfNotExists is idempotent — re-running on an already-migrated DB is safe.
	for _, col := range []struct{ decl string }{
		{"revoked_by TEXT"},
		{"revoked_at DATETIME"},
	} {
		if err := s.addColumnIfNotExists("credentials", col.decl); err != nil {
			return fmt.Errorf("migrate credentials: add %s: %w", col.decl, err)
		}
	}

	return nil
}

// addColumnIfNotExists applies "ALTER TABLE tbl ADD COLUMN decl" and silently
// ignores the "duplicate column name" error that SQLite returns when the column
// already exists — the only way to make ADD COLUMN idempotent in SQLite.
func (s *Store) addColumnIfNotExists(table, decl string) error {
	_, err := s.db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s`, table, decl))
	if err != nil && strings.Contains(err.Error(), "duplicate column name") {
		return nil
	}
	return err
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
		`SELECT id, principal_id, type, data, label, created_at, revoked_by, revoked_at FROM credentials WHERE id = ?`, id,
	)
	return scanCredential(row)
}

// ListCredentialsByPrincipal returns all credentials for the given principal,
// ordered by creation time.
func (s *Store) ListCredentialsByPrincipal(principalID string) ([]*Credential, error) {
	rows, err := s.db.Query(
		`SELECT id, principal_id, type, data, label, created_at, revoked_by, revoked_at FROM credentials WHERE principal_id = ? ORDER BY created_at`,
		principalID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list credentials: %w", err)
	}
	defer rows.Close()
	return collectCredentials(rows)
}

// RevokeCredential marks a credential as revoked.
// Returns ErrNotFound if no such credential exists.
// Returns ErrCredentialRevoked if the credential is already revoked.
func (s *Store) RevokeCredential(id, revokedByExternalID string) error {
	// Fetch current state first to distinguish not-found from already-revoked.
	row := s.db.QueryRow(`SELECT revoked_at FROM credentials WHERE id = ?`, id)
	var revokedAt sql.NullString
	if err := row.Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: revoke credential fetch: %w", err)
	}
	if revokedAt.Valid {
		return ErrCredentialRevoked
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE credentials SET revoked_by = ?, revoked_at = ? WHERE id = ?`,
		revokedByExternalID, now, id,
	)
	if err != nil {
		return fmt.Errorf("store: revoke credential: %w", err)
	}
	return nil
}

// UpdateCredentialData replaces the data BLOB for an existing credential.
// Used after a successful WebAuthn authentication to persist the updated sign count.
// Returns ErrNotFound if no such credential exists.
func (s *Store) UpdateCredentialData(id string, data []byte) error {
	res, err := s.db.Exec(`UPDATE credentials SET data = ? WHERE id = ?`, data, id)
	if err != nil {
		return fmt.Errorf("store: update credential data: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("store: update credential data rows-affected: %w", err)
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
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
	var revokedBy sql.NullString
	var revokedAt sql.NullString
	if err := row.Scan(&c.ID, &c.PrincipalID, (*string)(&c.Type), &c.Data, &c.Label, &createdAt, &revokedBy, &revokedAt); err != nil {
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
	if revokedBy.Valid {
		s := revokedBy.String
		c.RevokedBy = &s
	}
	if revokedAt.Valid {
		rt, err := parseTime(revokedAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse credential revoked_at: %w", err)
		}
		c.RevokedAt = &rt
	}
	return c, nil
}

func collectCredentials(rows *sql.Rows) ([]*Credential, error) {
	var result []*Credential
	for rows.Next() {
		c := &Credential{}
		var createdAt string
		var revokedBy sql.NullString
		var revokedAt sql.NullString
		if err := rows.Scan(&c.ID, &c.PrincipalID, (*string)(&c.Type), &c.Data, &c.Label, &createdAt, &revokedBy, &revokedAt); err != nil {
			return nil, fmt.Errorf("store: scan credential row: %w", err)
		}
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse credential timestamp: %w", err)
		}
		c.CreatedAt = t
		if revokedBy.Valid {
			s := revokedBy.String
			c.RevokedBy = &s
		}
		if revokedAt.Valid {
			rt, err := parseTime(revokedAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse credential revoked_at: %w", err)
			}
			c.RevokedAt = &rt
		}
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

// HashToken returns the hex-encoded SHA-256 of rawToken.
// This is the value stored in the enrolment_invites table.
func HashToken(rawToken string) string {
	sum := sha256.Sum256([]byte(rawToken))
	return hex.EncodeToString(sum[:])
}

// ReplaceWebAuthnCredentialAndConsumeInvite atomically:
//  1. Deletes all existing WebAuthn credentials for principalID.
//  2. Inserts a new WebAuthn credential.
//  3. Marks the enrolment invite identified by rawToken as used.
//
// All three steps execute in a single SQLite transaction. This ensures that a
// re-enrolment (recovery) wipes the old compromised passkey, registers the new
// one, and consumes the invite — or rolls back entirely on any failure.
// Returns the newly created Credential on success.
func (s *Store) ReplaceWebAuthnCredentialAndConsumeInvite(principalID, rawToken string, data []byte, label string) (*Credential, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck — deferred rollback is a no-op after commit

	// 1. Wipe all existing WebAuthn credentials for this principal.
	if _, err := tx.Exec(
		`DELETE FROM credentials WHERE principal_id = ? AND type = 'webauthn'`,
		principalID,
	); err != nil {
		return nil, fmt.Errorf("store: delete existing webauthn credentials: %w", err)
	}

	// 2. Insert the new credential.
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("store: generate credential id: %w", err)
	}
	now := time.Now().UTC()
	if _, err := tx.Exec(
		`INSERT INTO credentials (id, principal_id, type, data, label, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
		id, principalID, string(CredentialTypeWebAuthn), data, label, now.Format(time.RFC3339),
	); err != nil {
		return nil, fmt.Errorf("store: insert new credential: %w", err)
	}

	// 3. Consume the invite (set used_at).
	tokenHash := HashToken(rawToken)
	res, err := tx.Exec(
		`UPDATE enrolment_invites SET used_at = ? WHERE token_hash = ? AND used_at IS NULL`,
		now.Format(time.RFC3339), tokenHash,
	)
	if err != nil {
		return nil, fmt.Errorf("store: consume invite: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, fmt.Errorf("store: consume invite rows-affected: %w", err)
	}
	if n == 0 {
		// Either the invite doesn't exist or it was already used — both are
		// unexpected at this point in the flow (begin already validated it).
		return nil, ErrInviteUsed
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit transaction: %w", err)
	}

	return &Credential{
		ID:          id,
		PrincipalID: principalID,
		Type:        CredentialTypeWebAuthn,
		Data:        data,
		Label:       label,
		CreatedAt:   now,
	}, nil
}

// --- IdP session store (ADR-0003 §1) ---

// IdPSessionTTL is the lifetime of a long-lived IdP session.
// 72 hours (3 working days) is the chosen cap — enough for a full working session,
// short enough to bound the silent re-mint window. Documented here per ADR-0003
// ("pick and record the value").
const IdPSessionTTL = 72 * time.Hour

// CreateIDPSession creates a new long-lived IdP session for principalID.
// Returns the raw (unhashed) token, which must be delivered to the client as a cookie
// and never stored. Only the SHA-256 hash is persisted in the database.
func (s *Store) CreateIDPSession(principalID string) (string, *IDPSession, error) {
	rawToken, err := generateRawToken()
	if err != nil {
		return "", nil, fmt.Errorf("store: generate idp session token: %w", err)
	}
	hash := HashToken(rawToken)
	now := time.Now().UTC()
	expiresAt := now.Add(IdPSessionTTL)
	_, err = s.db.Exec(
		`INSERT INTO idp_sessions (token_hash, principal_id, created_at, expires_at)
		 VALUES (?, ?, ?, ?)`,
		hash, principalID, now.Format(time.RFC3339), expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		if isFKViolation(err) {
			return "", nil, ErrNotFound // principal doesn't exist
		}
		return "", nil, fmt.Errorf("store: create idp session: %w", err)
	}
	session := &IDPSession{
		TokenHash:   hash,
		PrincipalID: principalID,
		CreatedAt:   now,
		ExpiresAt:   expiresAt,
	}
	return rawToken, session, nil
}

// GetIDPSessionByToken looks up an IdP session by raw (unhashed) token.
// Returns ErrNotFound if the token does not exist.
// Returns ErrIDPSessionRevoked if the session has been explicitly revoked.
// Returns ErrIDPSessionExpired if the session has passed its expires_at.
// Callers must check these errors; using an expired or revoked session is not allowed.
func (s *Store) GetIDPSessionByToken(rawToken string) (*IDPSession, error) {
	hash := HashToken(rawToken)
	row := s.db.QueryRow(
		`SELECT token_hash, principal_id, created_at, expires_at, revoked_at
		 FROM idp_sessions WHERE token_hash = ?`,
		hash,
	)
	sess := &IDPSession{}
	var createdAt, expiresAt string
	var revokedAt sql.NullString
	if err := row.Scan(&sess.TokenHash, &sess.PrincipalID, &createdAt, &expiresAt, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan idp session: %w", err)
	}
	var err error
	sess.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse idp session created_at: %w", err)
	}
	sess.ExpiresAt, err = parseTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse idp session expires_at: %w", err)
	}
	if revokedAt.Valid {
		t, err := parseTime(revokedAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse idp session revoked_at: %w", err)
		}
		sess.RevokedAt = &t
		return nil, ErrIDPSessionRevoked
	}
	if sess.ExpiresAt.Before(time.Now()) {
		return nil, ErrIDPSessionExpired
	}
	return sess, nil
}

// RevokeIDPSessionsForPrincipal marks all active IdP sessions for principalID as
// revoked, effective immediately. This is the load-bearing revocation step in
// Scenario A of the credential-compromise runbook: after revoking a passkey, also
// call this so the re-mint endpoint cannot issue fresh access tokens.
// Returns the number of sessions revoked.
func (s *Store) RevokeIDPSessionsForPrincipal(principalID string) (int, error) {
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := s.db.Exec(
		`UPDATE idp_sessions SET revoked_at = ?
		 WHERE principal_id = ? AND revoked_at IS NULL`,
		now, principalID,
	)
	if err != nil {
		return 0, fmt.Errorf("store: revoke idp sessions: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store: revoke idp sessions rows-affected: %w", err)
	}
	return int(n), nil
}

// RevokeIDPSessionByToken marks the single IdP session identified by rawToken as
// revoked, effective immediately. This is called by handleLogout to invalidate the
// server-side record when the user explicitly logs out, so the token cannot be
// exploited even if captured before the browser discarded the cookie.
// Returns without error if the token is not found or already revoked.
func (s *Store) RevokeIDPSessionByToken(rawToken string) error {
	hash := HashToken(rawToken)
	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE idp_sessions SET revoked_at = ?
		 WHERE token_hash = ? AND revoked_at IS NULL`,
		now, hash,
	)
	if err != nil {
		return fmt.Errorf("store: revoke idp session by token: %w", err)
	}
	return nil
}

// ListAllowedCORSOrigins returns the set of HTTPS origins that are permitted to
// make credentialed cross-site fetch() calls to the re-mint endpoint (ADR-0003 §2).
// Origins are derived from the registered OIDC clients' redirect_uris: any origin
// whose redirect_uri is registered is considered a consumer of aithne and is allowed
// to trigger re-mints. This keeps the allow-list self-maintaining — registering a
// new OIDC client automatically grants it re-mint CORS access.
func (s *Store) ListAllowedCORSOrigins() ([]string, error) {
	rows, err := s.db.Query(`SELECT redirect_uris FROM oidc_clients`)
	if err != nil {
		return nil, fmt.Errorf("store: list cors origins: %w", err)
	}
	defer rows.Close()

	seen := map[string]struct{}{}
	var origins []string
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, fmt.Errorf("store: scan redirect_uris: %w", err)
		}
		var uris []string
		if err := json.Unmarshal([]byte(raw), &uris); err != nil {
			continue // malformed JSON — skip silently
		}
		for _, u := range uris {
			origin := extractOrigin(u)
			if origin == "" {
				continue
			}
			if _, dup := seen[origin]; !dup {
				seen[origin] = struct{}{}
				origins = append(origins, origin)
			}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate cors origins: %w", err)
	}
	return origins, nil
}

// extractOrigin returns the scheme+host part of a URI string (e.g.
// "https://photos.l42.eu" from "https://photos.l42.eu/auth/callback").
// Returns "" if the URI cannot be parsed or has no scheme/host.
func extractOrigin(rawURI string) string {
	// Fast path: avoid net/url import by scanning for the third slash.
	if rawURI == "" {
		return ""
	}
	// Find "://"
	schemeEnd := strings.Index(rawURI, "://")
	if schemeEnd < 0 {
		return ""
	}
	rest := rawURI[schemeEnd+3:]
	// Host ends at the first "/" or end of string.
	hostEnd := strings.IndexByte(rest, '/')
	var host string
	if hostEnd < 0 {
		host = rest
	} else {
		host = rest[:hostEnd]
	}
	if host == "" {
		return ""
	}
	return rawURI[:schemeEnd] + "://" + host
}

// generateRawToken returns a 32-byte cryptographically random token encoded as
// hex. The caller must store only the SHA-256 hash, not the raw value.
func generateRawToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
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
