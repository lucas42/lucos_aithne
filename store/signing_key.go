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

// MigrateSigningKeyEncryption detects any signing keys stored in the legacy
// unencrypted PKCS8 DER format and re-encrypts them in-place using the
// store's KEK. Call once at startup, before any other signing-key operations.
//
// Background: prior to this function the signing_keys table stored raw PKCS8
// DER bytes. Any existing rows written before AES-GCM encryption was added
// will fail the normal decrypt path. This function migrates those rows
// transparently so the service can continue to use existing keys rather than
// discarding them (which would immediately invalidate any in-flight tokens).
//
// Returns the number of rows that were migrated (0 on a fresh or already-
// migrated database).
func (s *Store) MigrateSigningKeyEncryption() (int, error) {
	rows, err := s.db.Query(`SELECT id, private_key FROM signing_keys`)
	if err != nil {
		return 0, fmt.Errorf("store: migrate signing key encryption: query: %w", err)
	}
	defer rows.Close()

	type entry struct {
		id  string
		raw []byte
	}
	var toMigrate []entry
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return 0, fmt.Errorf("store: migrate signing key encryption: scan: %w", err)
		}
		// Try to decrypt with the KEK first. If it succeeds the key is already
		// in the encrypted format — nothing to do.
		if _, err := decryptKeyDER(s.kek, blob); err == nil {
			continue
		}
		// Decryption failed. Check whether the blob is a raw PKCS8 DER (legacy
		// unencrypted format). If so, queue it for re-encryption.
		if _, err := x509.ParsePKCS8PrivateKey(blob); err != nil {
			return 0, fmt.Errorf("store: migrate signing key encryption: key %q is neither AES-GCM ciphertext nor valid PKCS8 DER — database may be corrupt: %w", id, err)
		}
		toMigrate = append(toMigrate, entry{id: id, raw: blob})
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: migrate signing key encryption: iterate: %w", err)
	}
	// Close rows before issuing UPDATEs (single-connection SQLite).
	rows.Close()

	for _, e := range toMigrate {
		encrypted, err := encryptKeyDER(s.kek, e.raw)
		if err != nil {
			return 0, fmt.Errorf("store: migrate signing key encryption: encrypt key %q: %w", e.id, err)
		}
		if _, err := s.db.Exec(`UPDATE signing_keys SET private_key = ? WHERE id = ?`, encrypted, e.id); err != nil {
			return 0, fmt.Errorf("store: migrate signing key encryption: update key %q: %w", e.id, err)
		}
	}
	return len(toMigrate), nil
}

// RekeySigningKeys re-encrypts all signing key BLOBs (active and retired) under
// newKek. Call with the service stopped: a concurrent RotateSigningKey during
// re-keying would create a race on the SQLite write even though SQLite's
// single-connection serialises it. Safer to stop the service first.
//
// Safety properties:
//   - If decryption of any key with the Store's current KEK fails, the call aborts
//     immediately and the DB is not modified.
//   - A round-trip decrypt with newKek is performed for every key before any UPDATE
//     is issued, catching silent bit-flips or library bugs.
//   - All UPDATEs run inside a single transaction; a mid-update error rolls back the
//     entire batch — partial re-keying is never committed to the DB.
//   - All rows are read into memory before any write (SQLite single-connection
//     constraint: an open read cursor blocks UPDATEs on the same connection).
//
// Returns the count of rows re-keyed. Returns (0, nil) if newKek == s.kek (no-op).
func (s *Store) RekeySigningKeys(newKek [32]byte) (int, error) {
	if newKek == s.kek {
		return 0, nil
	}

	// Step 1: read all rows into memory (cursor closed before any write).
	rows, err := s.db.Query(`SELECT id, private_key FROM signing_keys`)
	if err != nil {
		return 0, fmt.Errorf("store: rekey signing keys: query: %w", err)
	}
	defer rows.Close()

	type entry struct {
		id      string
		newBlob []byte
	}
	var pending []entry
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return 0, fmt.Errorf("store: rekey signing keys: scan: %w", err)
		}
		// Decrypt with the current KEK — abort immediately if this fails.
		der, err := decryptKeyDER(s.kek, blob)
		if err != nil {
			return 0, fmt.Errorf("store: rekey signing keys: key %q: decrypt with old KEK failed (wrong KEK or corrupt DB): %w", id, err)
		}
		// Encrypt under the new KEK.
		newBlob, err := encryptKeyDER(newKek, der)
		if err != nil {
			return 0, fmt.Errorf("store: rekey signing keys: key %q: encrypt with new KEK: %w", id, err)
		}
		// Round-trip validation: decrypt with newKek and verify plaintext matches.
		roundTripped, err := decryptKeyDER(newKek, newBlob)
		if err != nil {
			return 0, fmt.Errorf("store: rekey signing keys: key %q: round-trip decrypt failed: %w", id, err)
		}
		if string(roundTripped) != string(der) {
			return 0, fmt.Errorf("store: rekey signing keys: key %q: round-trip plaintext mismatch — aborting", id)
		}
		pending = append(pending, entry{id: id, newBlob: newBlob})
	}
	if err := rows.Err(); err != nil {
		return 0, fmt.Errorf("store: rekey signing keys: iterate: %w", err)
	}
	// Close the cursor before issuing any UPDATEs (SQLite single-connection).
	rows.Close()

	if len(pending) == 0 {
		return 0, nil
	}

	// Step 2: apply all UPDATEs in a single transaction (all-or-nothing).
	tx, err := s.db.Begin()
	if err != nil {
		return 0, fmt.Errorf("store: rekey signing keys: begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is best-effort cleanup

	for _, e := range pending {
		if _, err := tx.Exec(`UPDATE signing_keys SET private_key = ? WHERE id = ?`, e.newBlob, e.id); err != nil {
			return 0, fmt.Errorf("store: rekey signing keys: update key %q: %w", e.id, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store: rekey signing keys: commit: %w", err)
	}

	return len(pending), nil
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
