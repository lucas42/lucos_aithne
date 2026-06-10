// Package store — scope-grant management.
//
// Per ADR-0001 §6, authorisation is the real gate. The grant store records
// "principal P is granted scope S in environment E" — default-deny (no row
// means no access), per-env, revocable, and attributable (every grant and
// revocation records the acting principal's externalID).
//
// Scope strings are validated against the embedded vocabulary at grant-creation
// time; ErrUnknownScope is returned for any string not in the allowlist.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"
)

// ErrUnknownScope is returned when a scope string is not in the vocabulary.
var ErrUnknownScope = errors.New("store: unknown scope (not in vocabulary)")

// ErrGrantRevoked is returned when attempting to revoke an already-revoked grant.
var ErrGrantRevoked = errors.New("store: grant is already revoked")

// Grant records that a principal has been granted a scope in a given environment.
type Grant struct {
	ID          string     // UUID v4
	PrincipalID string     // references principals.id
	Scope       string     // e.g. "aithne:admin", "render-ui"
	Environment string     // e.g. "development", "production"
	GrantedBy   string     // externalID of the grantor (contact-id or agent slug)
	GrantedAt   time.Time
	RevokedBy   *string    // non-nil if revoked
	RevokedAt   *time.Time // non-nil if revoked
}

// IsActive reports whether the grant has not been revoked.
func (g *Grant) IsActive() bool { return g.RevokedAt == nil }

// Vocabulary is the set of valid scope strings loaded at build time.
type Vocabulary struct {
	valid map[string]struct{}
}

// NewVocabulary creates a Vocabulary from a set of scope strings.
func NewVocabulary(scopes []string) *Vocabulary {
	v := &Vocabulary{valid: make(map[string]struct{}, len(scopes))}
	for _, s := range scopes {
		v.valid[s] = struct{}{}
	}
	return v
}

// Contains reports whether scope is a known valid scope string.
func (v *Vocabulary) Contains(scope string) bool {
	_, ok := v.valid[scope]
	return ok
}

// All returns a sorted list of all valid scope strings.
func (v *Vocabulary) All() []string {
	result := make([]string, 0, len(v.valid))
	for s := range v.valid {
		result = append(result, s)
	}
	sort.Strings(result)
	return result
}

// CreateGrant adds a new scope grant for the given principal.
// scope must be present in vocab; ErrUnknownScope is returned otherwise.
// Returns ErrNotFound if principalID does not reference a known principal.
// Returns ErrDuplicate if the (principal, scope, environment) triple already has an active grant.
func (s *Store) CreateGrant(principalID, scope, environment, grantedByExternalID string, vocab *Vocabulary) (*Grant, error) {
	if !vocab.Contains(scope) {
		return nil, ErrUnknownScope
	}
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("store: generate grant id: %w", err)
	}
	now := time.Now().UTC()
	_, err = s.db.Exec(
		`INSERT INTO grants (id, principal_id, scope, environment, granted_by, granted_at)
		 VALUES (?, ?, ?, ?, ?, ?)`,
		id, principalID, scope, environment, grantedByExternalID, now.Format(time.RFC3339),
	)
	if err != nil {
		if isFKViolation(err) {
			return nil, ErrNotFound // principal doesn't exist
		}
		if isUniqueViolation(err) {
			return nil, ErrDuplicate
		}
		return nil, fmt.Errorf("store: create grant: %w", err)
	}
	return &Grant{
		ID:          id,
		PrincipalID: principalID,
		Scope:       scope,
		Environment: environment,
		GrantedBy:   grantedByExternalID,
		GrantedAt:   now,
	}, nil
}

// RevokeGrant marks a grant as revoked.
// Returns ErrNotFound if no such grant exists.
// Returns ErrGrantRevoked if the grant is already revoked.
func (s *Store) RevokeGrant(id, revokedByExternalID string) error {
	// Fetch current state first to distinguish not-found from already-revoked.
	row := s.db.QueryRow(`SELECT revoked_at FROM grants WHERE id = ?`, id)
	var revokedAt sql.NullString
	if err := row.Scan(&revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrNotFound
		}
		return fmt.Errorf("store: revoke grant fetch: %w", err)
	}
	if revokedAt.Valid {
		return ErrGrantRevoked
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(
		`UPDATE grants SET revoked_by = ?, revoked_at = ? WHERE id = ?`,
		revokedByExternalID, now, id,
	)
	if err != nil {
		return fmt.Errorf("store: revoke grant: %w", err)
	}
	return nil
}

// ListGrants returns grants for a given principal in the given environment.
// If activeOnly is true, revoked grants are excluded.
// Pass empty string for environment to match all environments.
func (s *Store) ListGrants(principalID, environment string, activeOnly bool) ([]*Grant, error) {
	var (
		rows *sql.Rows
		err  error
	)
	switch {
	case environment != "" && activeOnly:
		rows, err = s.db.Query(
			`SELECT id, principal_id, scope, environment, granted_by, granted_at, revoked_by, revoked_at
			 FROM grants WHERE principal_id = ? AND environment = ? AND revoked_at IS NULL
			 ORDER BY granted_at`,
			principalID, environment,
		)
	case environment != "" && !activeOnly:
		rows, err = s.db.Query(
			`SELECT id, principal_id, scope, environment, granted_by, granted_at, revoked_by, revoked_at
			 FROM grants WHERE principal_id = ? AND environment = ?
			 ORDER BY granted_at`,
			principalID, environment,
		)
	case environment == "" && activeOnly:
		rows, err = s.db.Query(
			`SELECT id, principal_id, scope, environment, granted_by, granted_at, revoked_by, revoked_at
			 FROM grants WHERE principal_id = ? AND revoked_at IS NULL
			 ORDER BY granted_at`,
			principalID,
		)
	default: // no filter
		rows, err = s.db.Query(
			`SELECT id, principal_id, scope, environment, granted_by, granted_at, revoked_by, revoked_at
			 FROM grants WHERE principal_id = ?
			 ORDER BY granted_at`,
			principalID,
		)
	}
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	defer rows.Close()
	return collectGrants(rows)
}

// GetGrant returns a single grant by ID.
// Returns ErrNotFound if no such grant exists.
func (s *Store) GetGrant(id string) (*Grant, error) {
	row := s.db.QueryRow(
		`SELECT id, principal_id, scope, environment, granted_by, granted_at, revoked_by, revoked_at
		 FROM grants WHERE id = ?`, id,
	)
	return scanGrant(row)
}

// GetActiveScopes returns all active (non-revoked) scope strings granted to the
// given principal in the given environment.
func (s *Store) GetActiveScopes(principalID, environment string) ([]string, error) {
	grants, err := s.ListGrants(principalID, environment, true)
	if err != nil {
		return nil, err
	}
	scopes := make([]string, 0, len(grants))
	for _, g := range grants {
		scopes = append(scopes, g.Scope)
	}
	return scopes, nil
}

// --- Internal scan helpers ---

func scanGrant(row *sql.Row) (*Grant, error) {
	g := &Grant{}
	var grantedAt string
	var revokedBy sql.NullString
	var revokedAt sql.NullString
	if err := row.Scan(&g.ID, &g.PrincipalID, &g.Scope, &g.Environment, &g.GrantedBy, &grantedAt, &revokedBy, &revokedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan grant: %w", err)
	}
	t, err := parseTime(grantedAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse grant granted_at: %w", err)
	}
	g.GrantedAt = t
	if revokedBy.Valid {
		s := revokedBy.String
		g.RevokedBy = &s
	}
	if revokedAt.Valid {
		rt, err := parseTime(revokedAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse grant revoked_at: %w", err)
		}
		g.RevokedAt = &rt
	}
	return g, nil
}

func collectGrants(rows *sql.Rows) ([]*Grant, error) {
	var result []*Grant
	for rows.Next() {
		g := &Grant{}
		var grantedAt string
		var revokedBy sql.NullString
		var revokedAt sql.NullString
		if err := rows.Scan(&g.ID, &g.PrincipalID, &g.Scope, &g.Environment, &g.GrantedBy, &grantedAt, &revokedBy, &revokedAt); err != nil {
			return nil, fmt.Errorf("store: scan grant row: %w", err)
		}
		t, err := parseTime(grantedAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse grant granted_at: %w", err)
		}
		g.GrantedAt = t
		if revokedBy.Valid {
			s := revokedBy.String
			g.RevokedBy = &s
		}
		if revokedAt.Valid {
			rt, err := parseTime(revokedAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse grant revoked_at: %w", err)
			}
			g.RevokedAt = &rt
		}
		result = append(result, g)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate grants: %w", err)
	}
	return result, nil
}
