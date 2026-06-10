// Package store — enrolment invite management.
//
// An enrolment invite is a short-lived, single-use token that authorises a
// passkey registration ceremony for a specific contact. It is created by an
// admin and sent to the invitee.
//
// The raw token (a UUID v4) is only returned once — at creation time — and
// is never stored. The database holds SHA-256(rawToken) as token_hash, so a
// leaked SQLite file does not expose usable invite URLs.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// InviteTTL is the default lifetime of an enrolment invite.
const InviteTTL = 24 * time.Hour

// EnrolmentInvite is the stored record for a single-use passkey enrolment token.
type EnrolmentInvite struct {
	TokenHash string     // SHA-256(rawToken) hex — never the raw token
	ContactID string     // lucos_contacts external ID of the invitee
	CreatedBy string     // ExternalID of the admin who created the invite
	CreatedAt time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time // non-nil once the invite has been consumed
}

// IsValid reports whether the invite is usable: not expired and not yet used.
func (inv *EnrolmentInvite) IsValid(now time.Time) bool {
	return inv.UsedAt == nil && now.Before(inv.ExpiresAt)
}

// CreateInvite stores a new enrolment invite and returns it.
// rawToken is the caller-generated random token (UUID v4). It is hashed
// before storage; the hash is set on the returned struct's TokenHash field.
func (s *Store) CreateInvite(rawToken, contactID, createdBy string) (*EnrolmentInvite, error) {
	tokenHash := HashToken(rawToken)
	now := time.Now().UTC()
	expiresAt := now.Add(InviteTTL)
	_, err := s.db.Exec(
		`INSERT INTO enrolment_invites (token_hash, contact_id, created_by, created_at, expires_at)
		 VALUES (?, ?, ?, ?, ?)`,
		tokenHash, contactID, createdBy,
		now.Format(time.RFC3339), expiresAt.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("store: create invite: %w", err)
	}
	return &EnrolmentInvite{
		TokenHash: tokenHash,
		ContactID: contactID,
		CreatedBy: createdBy,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}, nil
}

// GetInviteByRawToken looks up an invite by the raw (unhashed) token.
// Returns ErrNotFound if no matching hash exists in the database.
// Returns ErrInviteExpired or ErrInviteUsed for invalid but existing records.
func (s *Store) GetInviteByRawToken(rawToken string) (*EnrolmentInvite, error) {
	tokenHash := HashToken(rawToken)
	row := s.db.QueryRow(
		`SELECT token_hash, contact_id, created_by, created_at, expires_at, used_at
		 FROM enrolment_invites WHERE token_hash = ?`,
		tokenHash,
	)
	inv, err := scanInvite(row)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if inv.UsedAt != nil {
		return inv, ErrInviteUsed
	}
	if now.After(inv.ExpiresAt) {
		return inv, ErrInviteExpired
	}
	return inv, nil
}

// --- Internal helpers ---

func scanInvite(row *sql.Row) (*EnrolmentInvite, error) {
	inv := &EnrolmentInvite{}
	var createdAt, expiresAt string
	var usedAtStr *string
	err := row.Scan(&inv.TokenHash, &inv.ContactID, &inv.CreatedBy, &createdAt, &expiresAt, &usedAtStr)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan invite: %w", err)
	}
	t1, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse invite created_at: %w", err)
	}
	inv.CreatedAt = t1
	t2, err := parseTime(expiresAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse invite expires_at: %w", err)
	}
	inv.ExpiresAt = t2
	if usedAtStr != nil {
		t3, err := parseTime(*usedAtStr)
		if err != nil {
			return nil, fmt.Errorf("store: parse invite used_at: %w", err)
		}
		inv.UsedAt = &t3
	}
	return inv, nil
}
