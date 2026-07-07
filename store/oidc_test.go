package store

import "testing"

func TestUpsertOIDCClient_CreatesNew(t *testing.T) {
	s := newTestStore(t)

	c, err := s.UpsertOIDCClient("my-rp", "hash1", "My RP", []string{"https://rp.test/cb"})
	if err != nil {
		t.Fatalf("UpsertOIDCClient: %v", err)
	}
	if c.ID != "my-rp" || c.SecretHash != "hash1" || c.ClientName != "My RP" {
		t.Errorf("unexpected client: %+v", c)
	}

	fetched, err := s.GetOIDCClient("my-rp")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}
	if fetched.SecretHash != "hash1" {
		t.Errorf("SecretHash: got %q, want %q", fetched.SecretHash, "hash1")
	}
}

func TestUpsertOIDCClient_UpdatesExisting(t *testing.T) {
	s := newTestStore(t)

	if _, err := s.UpsertOIDCClient("my-rp", "hash1", "My RP", []string{"https://rp.test/cb"}); err != nil {
		t.Fatalf("initial UpsertOIDCClient: %v", err)
	}
	original, err := s.GetOIDCClient("my-rp")
	if err != nil {
		t.Fatalf("GetOIDCClient: %v", err)
	}

	// Re-upsert with a rotated secret and a changed redirect URI / name.
	updated, err := s.UpsertOIDCClient("my-rp", "hash2", "My RP Renamed", []string{"https://rp.test/cb2"})
	if err != nil {
		t.Fatalf("second UpsertOIDCClient: %v", err)
	}
	if updated.SecretHash != "hash2" {
		t.Errorf("SecretHash: got %q, want %q", updated.SecretHash, "hash2")
	}
	if updated.ClientName != "My RP Renamed" {
		t.Errorf("ClientName: got %q, want %q", updated.ClientName, "My RP Renamed")
	}
	if len(updated.RedirectURIs) != 1 || updated.RedirectURIs[0] != "https://rp.test/cb2" {
		t.Errorf("RedirectURIs: got %v", updated.RedirectURIs)
	}
	// created_at must not change on update.
	if !updated.CreatedAt.Equal(original.CreatedAt) {
		t.Errorf("CreatedAt changed on update: got %v, want %v", updated.CreatedAt, original.CreatedAt)
	}

	all, err := s.ListOIDCClients()
	if err != nil {
		t.Fatalf("ListOIDCClients: %v", err)
	}
	if len(all) != 1 {
		t.Errorf("expected exactly 1 row after update-in-place, got %d", len(all))
	}
}
