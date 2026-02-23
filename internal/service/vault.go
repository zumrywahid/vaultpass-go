package service

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"time"

	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/repository"
)

var (
	ErrEntryIDRequired      = errors.New("entry_id is required")
	ErrEncryptedDataRequired = errors.New("encrypted_data is required")
	ErrEntryNotFound         = errors.New("vault entry not found")
)

// VaultService handles vault entry business logic.
type VaultService struct {
	repo *repository.VaultRepository
}

// NewVaultService creates a new VaultService.
func NewVaultService(repo *repository.VaultRepository) *VaultService {
	return &VaultService{repo: repo}
}

// CreateEntry creates a new vault entry for a user.
func (s *VaultService) CreateEntry(ctx context.Context, userID int64, req model.VaultEntryRequest) (model.VaultEntryResponse, error) {
	if req.EntryID == "" {
		return model.VaultEntryResponse{}, ErrEntryIDRequired
	}
	if req.EncryptedData == "" {
		return model.VaultEntryResponse{}, ErrEncryptedDataRequired
	}

	data, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return model.VaultEntryResponse{}, err
	}

	entry := model.VaultEntry{
		UserID:        userID,
		EntryID:       req.EntryID,
		EncryptedData: data,
		Version:       1,
	}

	if err := s.repo.Upsert(ctx, &entry); err != nil {
		return model.VaultEntryResponse{}, err
	}
	entry.UpdatedAt = time.Now().UTC()

	return model.VaultEntryResponse{
		EntryID:       entry.EntryID,
		EncryptedData: base64.StdEncoding.EncodeToString(entry.EncryptedData),
		Version:       entry.Version,
		UpdatedAt:     entry.UpdatedAt,
	}, nil
}

// UpdateEntry updates an existing vault entry.
func (s *VaultService) UpdateEntry(ctx context.Context, userID int64, entryID string, req model.VaultEntryRequest) (model.VaultEntryResponse, error) {
	if req.EncryptedData == "" {
		return model.VaultEntryResponse{}, ErrEncryptedDataRequired
	}

	data, err := base64.StdEncoding.DecodeString(req.EncryptedData)
	if err != nil {
		return model.VaultEntryResponse{}, err
	}

	existing, err := s.repo.GetByEntryID(ctx, userID, entryID)
	if err != nil {
		if errors.Is(err, repository.ErrEntryNotFound) {
			return model.VaultEntryResponse{}, ErrEntryNotFound
		}
		return model.VaultEntryResponse{}, err
	}

	entry := model.VaultEntry{
		UserID:        userID,
		EntryID:       entryID,
		EncryptedData: data,
		Version:       existing.Version + 1,
	}

	if err := s.repo.Upsert(ctx, &entry); err != nil {
		return model.VaultEntryResponse{}, err
	}
	entry.UpdatedAt = time.Now().UTC()

	return model.VaultEntryResponse{
		EntryID:       entry.EntryID,
		EncryptedData: base64.StdEncoding.EncodeToString(entry.EncryptedData),
		Version:       entry.Version,
		UpdatedAt:     entry.UpdatedAt,
	}, nil
}

// DeleteEntry soft-deletes a vault entry.
func (s *VaultService) DeleteEntry(ctx context.Context, userID int64, entryID string) error {
	err := s.repo.SoftDelete(ctx, userID, entryID)
	if errors.Is(err, repository.ErrEntryNotFound) {
		return ErrEntryNotFound
	}
	return err
}

// ListEntries returns all non-deleted vault entries for a user.
func (s *VaultService) ListEntries(ctx context.Context, userID int64) ([]model.VaultEntryResponse, error) {
	entries, err := s.repo.ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	return entriesToResponse(entries), nil
}

// Sync processes incoming client entries and returns server-side changes.
func (s *VaultService) Sync(ctx context.Context, userID int64, req model.SyncRequest) (model.SyncResponse, error) {
	syncedAt := time.Now().UTC()

	// Process incoming client entries within a transaction.
	var skipped int
	if len(req.Entries) > 0 {
		tx, err := s.repo.BeginTx(ctx)
		if err != nil {
			return model.SyncResponse{}, err
		}
		defer tx.Rollback()

		for _, re := range req.Entries {
			data, err := base64.StdEncoding.DecodeString(re.EncryptedData)
			if err != nil {
				slog.Warn("skipping entry: base64 decode failed", "entry_id", re.EntryID, "error", err)
				skipped++
				continue
			}

			version := re.Version
			if version < 1 {
				version = 1
			}

			entry := model.VaultEntry{
				UserID:        userID,
				EntryID:       re.EntryID,
				EncryptedData: data,
				Version:       version,
				Deleted:       re.Deleted,
			}

			if err := s.repo.UpsertTx(ctx, tx, &entry); err != nil {
				slog.Warn("skipping entry: upsert failed", "entry_id", re.EntryID, "error", err)
				skipped++
				continue
			}
		}

		if err := tx.Commit(); err != nil {
			return model.SyncResponse{}, err
		}
	}

	// Get server-side changes to send back to the client.
	var serverEntries []model.VaultEntry
	var err error

	if req.LastSyncedAt == nil {
		// First sync: return all entries including deleted.
		serverEntries, err = s.repo.GetChangedSince(ctx, userID, time.Time{})
	} else {
		serverEntries, err = s.repo.GetChangedSince(ctx, userID, *req.LastSyncedAt)
	}
	if err != nil {
		return model.SyncResponse{}, err
	}

	return model.SyncResponse{
		SyncedAt: syncedAt,
		Entries:  entriesToResponse(serverEntries),
		Skipped:  skipped,
	}, nil
}

// entriesToResponse converts a slice of VaultEntry to a slice of VaultEntryResponse.
func entriesToResponse(entries []model.VaultEntry) []model.VaultEntryResponse {
	result := make([]model.VaultEntryResponse, len(entries))
	for i, e := range entries {
		result[i] = model.VaultEntryResponse{
			EntryID:       e.EntryID,
			EncryptedData: base64.StdEncoding.EncodeToString(e.EncryptedData),
			Version:       e.Version,
			UpdatedAt:     e.UpdatedAt,
			Deleted:       e.Deleted,
		}
	}
	return result
}
