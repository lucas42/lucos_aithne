// Package store — signing key management.
//
// Signing keys are EC P-256 (ES256) keys used to mint and verify session JWTs.
// The key ID (UUID v4) is used as the JWK "kid" header so consumers can fetch
// the matching public key from /.well-known/jwks.json for local verification.
//
// At most one key is "active" (used for minting) at any time. Retired keys
// remain in the database so that tokens signed with them can still be verified
// until those tokens expire (see ListVerificationKeys).
package store

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"time"
)

// dbExec is a minimal interface satisfied by both *sql.DB and *sql.Tx,
// allowing key-generation helpers to be reused inside transactions.
type dbExec interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// SigningKey is an EC P-256 key used to sign and verify session JWTs.
type SigningKey struct {
	ID         string     // UUID v4 — used as JWK "kid"
	Algorithm  string     // always "ES256"
	PrivateKey []byte     // PKCS8 DER-encoded EC private key
	Status     string     // "active" | "retired"
	CreatedAt  time.Time
	RetiredAt  *time.Time // nil when active
}

// GetOrCreateActiveSigningKey returns the current active signing key.
// If no active key exists, a fresh ES256 key is generated and stored.
func (s *Store) GetOrCreateActiveSigningKey() (*SigningKey, error) {
	row := s.db.QueryRow(
		`SELECT id, algorithm, private_key, status, created_at, retired_at
		 FROM signing_keys WHERE status = 'active' LIMIT 1`,
	)
	k, err := scanSigningKey(row, s.kek)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	// No active key — generate one.
	return s.generateSigningKey()
}

// ListVerificationKeys returns all keys whose signatures may be in circulation:
// the active key plus any keys retired within verificationWindow of now.
// Pass a window >= the JWT TTL so all valid tokens can be verified.
func (s *Store) ListVerificationKeys(verificationWindow time.Duration) ([]*SigningKey, error) {
	cutoff := time.Now().UTC().Add(-verificationWindow).Format(time.RFC3339)
	rows, err := s.db.Query(
		`SELECT id, algorithm, private_key, status, created_at, retired_at
		 FROM signing_keys
		 WHERE status = 'active'
		    OR (status = 'retired' AND retired_at >= ?)
		 ORDER BY created_at DESC`,
		cutoff,
	)
	if err != nil {
		return nil, fmt.Errorf("store: list verification keys: %w", err)
	}
	defer rows.Close()
	return collectSigningKeys(rows, s.kek)
}

// RotateSigningKey atomically generates a new active signing key and retires
// the previous active key. The INSERT and UPDATE run inside a single transaction
// so a mid-rotation crash cannot leave the database with two active keys.
// Returns the new active key.
func (s *Store) RotateSigningKey() (*SigningKey, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("store: begin rotation tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a best-effort cleanup

	newKey, err := generateSigningKeyWith(tx, s.kek)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	_, err = tx.Exec(
		`UPDATE signing_keys SET status = 'retired', retired_at = ?
		 WHERE status = 'active' AND id != ?`,
		now, newKey.ID,
	)
	if err != nil {
		return nil, fmt.Errorf("store: retire old signing key: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: commit rotation tx: %w", err)
	}
	return newKey, nil
}

// RotateSigningKeyIfOlderThan rotates the active signing key if it was created
// more than maxAge ago. Returns (true, newKey, nil) if rotation occurred, or
// (false, nil, nil) if the key is still within the allowed age. Returns an
// error if rotation fails.
//
// This is the primary rotation trigger called at startup (main.go). Pass
// signingKeyRotationInterval (30 days) for normal operation; a zero or negative
// duration forces rotation (useful in tests).
func (s *Store) RotateSigningKeyIfOlderThan(maxAge time.Duration) (rotated bool, newKey *SigningKey, err error) {
	k, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		return false, nil, fmt.Errorf("store: check signing key age: %w", err)
	}
	if time.Since(k.CreatedAt) <= maxAge {
		return false, nil, nil
	}
	newKey, err = s.RotateSigningKey()
	if err != nil {
		return false, nil, fmt.Errorf("store: rotate signing key: %w", err)
	}
	return true, newKey, nil
}

// generateSigningKey creates a fresh ES256 key and inserts it as active
// using the store's main DB connection (non-transactional path).
func (s *Store) generateSigningKey() (*SigningKey, error) {
	return generateSigningKeyWith(s.db, s.kek)
}

// generateSigningKeyWith inserts a new active ES256 key using the provided executor
// (either *sql.DB or *sql.Tx). The private key DER is AES-256-GCM encrypted with
// kek before being stored in the database.
func generateSigningKeyWith(db dbExec, kek [32]byte) (*SigningKey, error) {
	id, err := newID()
	if err != nil {
		return nil, fmt.Errorf("store: generate signing key id: %w", err)
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("store: generate EC key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("store: marshal signing key: %w", err)
	}
	blob, err := encryptKeyDER(kek, der)
	if err != nil {
		return nil, fmt.Errorf("store: encrypt signing key: %w", err)
	}
	now := time.Now().UTC()
	_, err = db.Exec(
		`INSERT INTO signing_keys (id, algorithm, private_key, status, created_at)
		 VALUES (?, 'ES256', ?, 'active', ?)`,
		id, blob, now.Format(time.RFC3339),
	)
	if err != nil {
		return nil, fmt.Errorf("store: insert signing key: %w", err)
	}
	return &SigningKey{
		ID:         id,
		Algorithm:  "ES256",
		PrivateKey: der, // return plaintext DER to callers
		Status:     "active",
		CreatedAt:  now,
	}, nil
}

// encryptKeyDER AES-256-GCM encrypts plaintext DER key material.
// The returned blob has the format: 12-byte nonce || AES-GCM ciphertext+tag.
func encryptKeyDER(kek [32]byte, der []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	// Seal appends ciphertext+tag to nonce, producing nonce||ciphertext+tag.
	return gcm.Seal(nonce, nonce, der, nil), nil
}

// decryptKeyDER AES-256-GCM decrypts a blob produced by encryptKeyDER.
// Returns an error if the KEK is wrong or the ciphertext has been tampered with.
func decryptKeyDER(kek [32]byte, blob []byte) ([]byte, error) {
	block, err := aes.NewCipher(kek[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(blob) < gcm.NonceSize() {
		return nil, fmt.Errorf("blob too short to contain nonce (%d bytes)", len(blob))
	}
	nonce := blob[:gcm.NonceSize()]
	ct := blob[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

// --- Internal scan helpers ---

func scanSigningKey(row *sql.Row, kek [32]byte) (*SigningKey, error) {
	k := &SigningKey{}
	var encryptedDER []byte
	var createdAt string
	var retiredAt sql.NullString
	if err := row.Scan(&k.ID, &k.Algorithm, &encryptedDER, &k.Status, &createdAt, &retiredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("store: scan signing key: %w", err)
	}
	der, err := decryptKeyDER(kek, encryptedDER)
	if err != nil {
		return nil, fmt.Errorf("store: decrypt signing key %q: %w", k.ID, err)
	}
	k.PrivateKey = der
	t, err := parseTime(createdAt)
	if err != nil {
		return nil, fmt.Errorf("store: parse signing key created_at: %w", err)
	}
	k.CreatedAt = t
	if retiredAt.Valid {
		rt, err := parseTime(retiredAt.String)
		if err != nil {
			return nil, fmt.Errorf("store: parse signing key retired_at: %w", err)
		}
		k.RetiredAt = &rt
	}
	return k, nil
}

func collectSigningKeys(rows *sql.Rows, kek [32]byte) ([]*SigningKey, error) {
	var result []*SigningKey
	for rows.Next() {
		k := &SigningKey{}
		var encryptedDER []byte
		var createdAt string
		var retiredAt sql.NullString
		if err := rows.Scan(&k.ID, &k.Algorithm, &encryptedDER, &k.Status, &createdAt, &retiredAt); err != nil {
			return nil, fmt.Errorf("store: scan signing key row: %w", err)
		}
		der, err := decryptKeyDER(kek, encryptedDER)
		if err != nil {
			return nil, fmt.Errorf("store: decrypt signing key %q: %w", k.ID, err)
		}
		k.PrivateKey = der
		t, err := parseTime(createdAt)
		if err != nil {
			return nil, fmt.Errorf("store: parse signing key created_at: %w", err)
		}
		k.CreatedAt = t
		if retiredAt.Valid {
			rt, err := parseTime(retiredAt.String)
			if err != nil {
				return nil, fmt.Errorf("store: parse signing key retired_at: %w", err)
			}
			k.RetiredAt = &rt
		}
		result = append(result, k)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterate signing keys: %w", err)
	}
	return result, nil
}
