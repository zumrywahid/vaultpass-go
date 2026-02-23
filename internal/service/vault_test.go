package service

import (
	"context"
	"encoding/base64"
	"testing"

	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/repository"
)

func newTestVaultService() *VaultService {
	return NewVaultService(repository.NewVaultRepository(nil))
}

func TestCreateEntry_EmptyEntryID(t *testing.T) {
	svc := newTestVaultService()

	_, err := svc.CreateEntry(context.Background(), 1, model.VaultEntryRequest{
		EntryID:       "",
		EncryptedData: "dGVzdA==",
	})

	if err != ErrEntryIDRequired {
		t.Errorf("expected ErrEntryIDRequired, got %v", err)
	}
}

func TestCreateEntry_EmptyEncryptedData(t *testing.T) {
	svc := newTestVaultService()

	_, err := svc.CreateEntry(context.Background(), 1, model.VaultEntryRequest{
		EntryID:       "entry-1",
		EncryptedData: "",
	})

	if err != ErrEncryptedDataRequired {
		t.Errorf("expected ErrEncryptedDataRequired, got %v", err)
	}
}

func TestUpdateEntry_EmptyEncryptedData(t *testing.T) {
	svc := newTestVaultService()

	_, err := svc.UpdateEntry(context.Background(), 1, "entry-1", model.VaultEntryRequest{
		EncryptedData: "",
	})

	if err != ErrEncryptedDataRequired {
		t.Errorf("expected ErrEncryptedDataRequired, got %v", err)
	}
}

func TestEntriesToResponse_EmptySlice(t *testing.T) {
	result := entriesToResponse(nil)

	if result == nil {
		t.Fatal("expected non-nil empty slice, got nil")
	}
	if len(result) != 0 {
		t.Errorf("expected 0 entries, got %d", len(result))
	}
}

func TestEntriesToResponse_Base64Encoding(t *testing.T) {
	plaintext := []byte("secret-vault-data")

	entries := []model.VaultEntry{
		{
			EntryID:       "entry-1",
			EncryptedData: plaintext,
			Version:       3,
			Deleted:       false,
		},
	}

	result := entriesToResponse(entries)

	if len(result) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(result))
	}

	// Verify the response contains valid base64 that decodes back to the original bytes.
	decoded, err := base64.StdEncoding.DecodeString(result[0].EncryptedData)
	if err != nil {
		t.Fatalf("failed to decode base64: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Errorf("expected %q, got %q", plaintext, decoded)
	}
	if result[0].EntryID != "entry-1" {
		t.Errorf("expected entry_id 'entry-1', got %q", result[0].EntryID)
	}
	if result[0].Version != 3 {
		t.Errorf("expected version 3, got %d", result[0].Version)
	}
}
