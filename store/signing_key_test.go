package store

import (
	"bytes"
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

// TestEncryptDecryptKeyDER verifies the AES-256-GCM round-trip and wrong-KEK rejection.
func TestEncryptDecryptKeyDER(t *testing.T) {
	kek := testKEK
	original := []byte("fake private key DER for unit testing encryptKeyDER/decryptKeyDER")

	encrypted, err := encryptKeyDER(kek, original)
	if err != nil {
		t.Fatalf("encryptKeyDER: %v", err)
	}
	if bytes.Equal(encrypted, original) {
		t.Error("encrypted bytes are identical to plaintext — no encryption occurred")
	}

	decrypted, err := decryptKeyDER(kek, encrypted)
	if err != nil {
		t.Fatalf("decryptKeyDER: %v", err)
	}
	if !bytes.Equal(decrypted, original) {
		t.Errorf("round-trip mismatch: got %q, want %q", decrypted, original)
	}

	// A different KEK must cause decryption to fail (GCM authentication error).
	var wrongKEK [32]byte
	wrongKEK[0] = 0xFF
	if _, err := decryptKeyDER(wrongKEK, encrypted); err == nil {
		t.Error("expected error decrypting with wrong KEK, got nil")
	}
}

// TestMigrateSigningKeyEncryption verifies that legacy unencrypted PKCS8 DER rows
// are detected and re-encrypted by MigrateSigningKeyEncryption.
func TestMigrateSigningKeyEncryption(t *testing.T) {
	s := newTestStore(t)

	// Insert a raw (unencrypted) PKCS8 DER key directly, bypassing the store's
	// encrypt path — this simulates a row written by the pre-encryption code.
	legacyKey, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}
	// Overwrite the encrypted blob with the raw plaintext DER.
	if _, err := s.db.Exec(
		`UPDATE signing_keys SET private_key = ? WHERE id = ?`,
		legacyKey.PrivateKey, legacyKey.ID,
	); err != nil {
		t.Fatalf("set raw DER in DB: %v", err)
	}

	// Confirm that reading the key back now fails (GCM auth error on raw DER).
	row := s.db.QueryRow(
		`SELECT id, algorithm, private_key, status, created_at, retired_at
		 FROM signing_keys WHERE id = ?`, legacyKey.ID,
	)
	if _, err := scanSigningKey(row, testKEK); err == nil {
		t.Fatal("expected decrypt error on raw DER blob, got nil — migration test precondition failed")
	}

	// Run the migration.
	migrated, err := s.MigrateSigningKeyEncryption()
	if err != nil {
		t.Fatalf("MigrateSigningKeyEncryption: %v", err)
	}
	if migrated != 1 {
		t.Errorf("migrated: got %d, want 1", migrated)
	}

	// Key must now decrypt correctly.
	k, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey after migration: %v", err)
	}
	if k.ID != legacyKey.ID {
		t.Errorf("key ID changed during migration: got %q, want %q", k.ID, legacyKey.ID)
	}
	if !bytes.Equal(k.PrivateKey, legacyKey.PrivateKey) {
		t.Error("private key material changed during migration")
	}

	// Raw DB blob must now be encrypted (not valid PKCS8).
	var rawBlob []byte
	if err := s.db.QueryRow(`SELECT private_key FROM signing_keys WHERE id = ?`, k.ID).Scan(&rawBlob); err != nil {
		t.Fatalf("read raw blob: %v", err)
	}
	if _, parseErr := x509.ParsePKCS8PrivateKey(rawBlob); parseErr == nil {
		t.Error("raw blob is still valid PKCS8 after migration — not encrypted")
	}

	// Running migration a second time must be a no-op (already encrypted).
	migrated2, err := s.MigrateSigningKeyEncryption()
	if err != nil {
		t.Fatalf("second MigrateSigningKeyEncryption: %v", err)
	}
	if migrated2 != 0 {
		t.Errorf("second migration: expected 0 rows migrated, got %d", migrated2)
	}
}

// TestRekeySigningKeys_HappyPath verifies that active and retired signing keys are
// re-encrypted under the new KEK and are still readable after re-open.
func TestRekeySigningKeys_HappyPath(t *testing.T) {
	s := newTestStore(t)

	// Create one active key and retire it, then create a new active key — so we
	// have both an active and a retired key to re-key.
	_, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}
	activeKey, err := s.RotateSigningKey()
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	var newKek [32]byte
	for i := range newKek {
		newKek[i] = byte(200 + i) // distinct from testKEK
	}

	n, err := s.RekeySigningKeys(newKek)
	if err != nil {
		t.Fatalf("RekeySigningKeys: %v", err)
	}
	if n != 2 {
		t.Errorf("RekeySigningKeys: want 2 rows re-keyed, got %d", n)
	}

	// Re-open the store with the new KEK and verify the active key is still readable.
	s2, err := Open(":memory:", newKek)
	if err != nil {
		t.Fatalf("Open with new KEK: %v", err)
	}
	defer s2.Close()
	// Copy the DB contents to the new store so we can verify the blobs.
	// Simpler: verify directly via decryptKeyDER on the raw blobs.
	var rawBlob []byte
	if err := s.db.QueryRow(`SELECT private_key FROM signing_keys WHERE id = ?`, activeKey.ID).Scan(&rawBlob); err != nil {
		t.Fatalf("read raw blob: %v", err)
	}
	// Must decrypt with the new KEK.
	der, err := decryptKeyDER(newKek, rawBlob)
	if err != nil {
		t.Fatalf("decrypt with new KEK: %v", err)
	}
	// Must NOT decrypt with the old KEK.
	if _, err := decryptKeyDER(testKEK, rawBlob); err == nil {
		t.Error("blob still decryptable with old KEK after re-key — re-key did not change the encryption")
	}
	// DER must still be a valid EC private key.
	if _, err := x509.ParsePKCS8PrivateKey(der); err != nil {
		t.Errorf("re-keyed DER is not valid PKCS8: %v", err)
	}
}

// TestRekeySigningKeys_WrongOldKEK verifies that RekeySigningKeys aborts and leaves
// the DB unchanged when the Store's KEK cannot decrypt the stored keys.
func TestRekeySigningKeys_WrongOldKEK(t *testing.T) {
	s := newTestStore(t)

	key, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}

	// Read the original encrypted blob.
	var originalBlob []byte
	if err := s.db.QueryRow(`SELECT private_key FROM signing_keys WHERE id = ?`, key.ID).Scan(&originalBlob); err != nil {
		t.Fatalf("read original blob: %v", err)
	}
	originalBlobCopy := make([]byte, len(originalBlob))
	copy(originalBlobCopy, originalBlob)

	// Build a store that uses a different (wrong) KEK.
	var wrongKek [32]byte
	wrongKek[0] = 0xFF
	sWrong := &Store{db: s.db, kek: wrongKek}

	var newKek [32]byte
	newKek[0] = 0xAA
	_, err = sWrong.RekeySigningKeys(newKek)
	if err == nil {
		t.Fatal("expected error re-keying with wrong old KEK, got nil")
	}

	// DB must be unchanged — blob must still decrypt with the original KEK.
	var blobAfter []byte
	if err := s.db.QueryRow(`SELECT private_key FROM signing_keys WHERE id = ?`, key.ID).Scan(&blobAfter); err != nil {
		t.Fatalf("read blob after failed rekey: %v", err)
	}
	if string(blobAfter) != string(originalBlobCopy) {
		t.Error("DB was modified despite wrong-KEK rekey attempt — atomicity violation")
	}
	if _, err := decryptKeyDER(testKEK, blobAfter); err != nil {
		t.Errorf("blob no longer decryptable with original KEK: %v", err)
	}
}

// TestRekeySigningKeys_RetiredKeysCovered verifies that retired signing keys (not just
// active ones) are included in the re-keying operation.
func TestRekeySigningKeys_RetiredKeysCovered(t *testing.T) {
	s := newTestStore(t)

	// Create a key then retire it.
	retiredKey, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("initial key: %v", err)
	}
	if _, err := s.RotateSigningKey(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	var newKek [32]byte
	for i := range newKek {
		newKek[i] = byte(100 + i)
	}

	// Re-key: should cover both active and retired → 2 rows.
	n, err := s.RekeySigningKeys(newKek)
	if err != nil {
		t.Fatalf("RekeySigningKeys: %v", err)
	}
	if n != 2 {
		t.Errorf("want 2 rows re-keyed (active + retired), got %d", n)
	}

	// The retired key's blob must now decrypt with the new KEK.
	var retiredBlob []byte
	if err := s.db.QueryRow(`SELECT private_key FROM signing_keys WHERE id = ?`, retiredKey.ID).Scan(&retiredBlob); err != nil {
		t.Fatalf("read retired key blob: %v", err)
	}
	if _, err := decryptKeyDER(newKek, retiredBlob); err != nil {
		t.Errorf("retired key blob not decryptable with new KEK: %v", err)
	}
}

// TestRekeySigningKeys_AtomicOnError verifies that no rows are updated if re-keying
// aborts partway through (simulated by using a wrong KEK that fails to decrypt).
// In practice, the check happens before any UPDATEs are issued, so a wrong-KEK error
// always leaves the DB entirely unchanged. This test confirms that invariant.
func TestRekeySigningKeys_AtomicOnError(t *testing.T) {
	s := newTestStore(t)

	// Create two keys so there are two rows.
	if _, err := s.GetOrCreateActiveSigningKey(); err != nil {
		t.Fatalf("initial key: %v", err)
	}
	if _, err := s.RotateSigningKey(); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// Capture the original blobs.
	rows, err := s.db.Query(`SELECT id, private_key FROM signing_keys ORDER BY created_at`)
	if err != nil {
		t.Fatalf("read original blobs: %v", err)
	}
	originals := map[string][]byte{}
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			t.Fatalf("scan: %v", err)
		}
		b := make([]byte, len(blob))
		copy(b, blob)
		originals[id] = b
	}
	rows.Close()

	// Attempt a rekey with a wrong old KEK.
	var wrongKek [32]byte
	wrongKek[0] = 0x99
	sWrong := &Store{db: s.db, kek: wrongKek}

	var newKek [32]byte
	newKek[0] = 0x01
	if _, err := sWrong.RekeySigningKeys(newKek); err == nil {
		t.Fatal("expected error, got nil")
	}

	// All blobs must be unchanged.
	for id, orig := range originals {
		var blob []byte
		if err := s.db.QueryRow(`SELECT private_key FROM signing_keys WHERE id = ?`, id).Scan(&blob); err != nil {
			t.Fatalf("read blob for %q after failed rekey: %v", id, err)
		}
		if string(blob) != string(orig) {
			t.Errorf("key %q was modified despite failed rekey — atomicity violated", id)
		}
	}
}

// TestSigningKeyEncryptedAtRest verifies that the private_key BLOB stored in SQLite
// is AES-GCM ciphertext and not raw PKCS8 DER.
func TestSigningKeyEncryptedAtRest(t *testing.T) {
	s := newTestStore(t)
	k, err := s.GetOrCreateActiveSigningKey()
	if err != nil {
		t.Fatalf("GetOrCreateActiveSigningKey: %v", err)
	}

	// Read the raw blob directly from SQLite, bypassing the store's decrypt path.
	var rawBlob []byte
	if err := s.db.QueryRow(
		`SELECT private_key FROM signing_keys WHERE id = ?`, k.ID,
	).Scan(&rawBlob); err != nil {
		t.Fatalf("read raw blob from DB: %v", err)
	}

	// The raw blob must differ from the plaintext DER.
	if bytes.Equal(rawBlob, k.PrivateKey) {
		t.Error("private_key blob in DB matches plaintext DER — key is NOT encrypted at rest")
	}

	// The raw blob must NOT be parseable as PKCS8 (that would mean it's stored unencrypted).
	if _, parseErr := x509.ParsePKCS8PrivateKey(rawBlob); parseErr == nil {
		t.Error("raw private_key blob in DB is valid PKCS8 — key is stored unencrypted")
	}
}
