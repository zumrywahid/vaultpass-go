package repository

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/vaultpass/vaultpass-go/internal/model"
)

var ErrEntryNotFound = errors.New("vault entry not found")

// VaultRepository handles vault entry persistence operations.
type VaultRepository struct {
	db *sql.DB
}

// NewVaultRepository creates a new VaultRepository.
func NewVaultRepository(db *sql.DB) *VaultRepository {
	return &VaultRepository{db: db}
}

// upsertQuery is the shared SQL for insert-or-update with LWW conflict resolution.
const upsertQuery = `
	INSERT INTO vault_entries (user_id, entry_id, encrypted_data, version, deleted)
	VALUES (?, ?, ?, ?, ?)
	ON DUPLICATE KEY UPDATE
		encrypted_data = IF(VALUES(version) > version, VALUES(encrypted_data), encrypted_data),
		version        = IF(VALUES(version) > version, VALUES(version), version),
		deleted        = IF(VALUES(version) > version, VALUES(deleted), deleted),
		updated_at     = IF(VALUES(version) > version, CURRENT_TIMESTAMP, updated_at)`

// BeginTx starts a new database transaction.
func (r *VaultRepository) BeginTx(ctx context.Context) (*sql.Tx, error) {
	return r.db.BeginTx(ctx, nil)
}

// Upsert inserts or updates a vault entry using last-write-wins conflict resolution.
// The entry is only updated if the incoming version is greater than the existing version.
func (r *VaultRepository) Upsert(ctx context.Context, entry *model.VaultEntry) error {
	_, err := r.db.ExecContext(ctx, upsertQuery,
		entry.UserID,
		entry.EntryID,
		entry.EncryptedData,
		entry.Version,
		entry.Deleted,
	)
	return err
}

// UpsertTx inserts or updates a vault entry within the provided transaction.
func (r *VaultRepository) UpsertTx(ctx context.Context, tx *sql.Tx, entry *model.VaultEntry) error {
	_, err := tx.ExecContext(ctx, upsertQuery,
		entry.UserID,
		entry.EntryID,
		entry.EncryptedData,
		entry.Version,
		entry.Deleted,
	)
	return err
}

// GetByEntryID retrieves a vault entry by user ID and client-generated entry ID.
func (r *VaultRepository) GetByEntryID(ctx context.Context, userID int64, entryID string) (*model.VaultEntry, error) {
	query := `SELECT id, user_id, entry_id, encrypted_data, version, created_at, updated_at, deleted
		FROM vault_entries WHERE user_id = ? AND entry_id = ?`

	entry := &model.VaultEntry{}
	err := r.db.QueryRowContext(ctx, query, userID, entryID).Scan(
		&entry.ID, &entry.UserID, &entry.EntryID, &entry.EncryptedData,
		&entry.Version, &entry.CreatedAt, &entry.UpdatedAt, &entry.Deleted,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEntryNotFound
		}
		return nil, err
	}

	return entry, nil
}

// ListByUser retrieves all non-deleted vault entries for a user, ordered by most recently updated.
func (r *VaultRepository) ListByUser(ctx context.Context, userID int64) ([]model.VaultEntry, error) {
	query := `SELECT id, user_id, entry_id, encrypted_data, version, created_at, updated_at, deleted
		FROM vault_entries WHERE user_id = ? AND deleted = FALSE ORDER BY updated_at DESC`

	rows, err := r.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []model.VaultEntry
	for rows.Next() {
		var e model.VaultEntry
		if err := rows.Scan(
			&e.ID, &e.UserID, &e.EntryID, &e.EncryptedData,
			&e.Version, &e.CreatedAt, &e.UpdatedAt, &e.Deleted,
		); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	return entries, rows.Err()
}

// GetChangedSince retrieves all vault entries (including deleted) modified after the given timestamp.
// This is used during sync to send changed entries back to the client.
func (r *VaultRepository) GetChangedSince(ctx context.Context, userID int64, since time.Time) ([]model.VaultEntry, error) {
	query := `SELECT id, user_id, entry_id, encrypted_data, version, created_at, updated_at, deleted
		FROM vault_entries WHERE user_id = ? AND updated_at > ? ORDER BY updated_at ASC`

	rows, err := r.db.QueryContext(ctx, query, userID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var entries []model.VaultEntry
	for rows.Next() {
		var e model.VaultEntry
		if err := rows.Scan(
			&e.ID, &e.UserID, &e.EntryID, &e.EncryptedData,
			&e.Version, &e.CreatedAt, &e.UpdatedAt, &e.Deleted,
		); err != nil {
			return nil, err
		}
		entries = append(entries, e)
	}

	return entries, rows.Err()
}

// SoftDelete marks a vault entry as deleted and increments its version for sync propagation.
func (r *VaultRepository) SoftDelete(ctx context.Context, userID int64, entryID string) error {
	query := `UPDATE vault_entries SET deleted = TRUE, version = version + 1
		WHERE user_id = ? AND entry_id = ?`

	result, err := r.db.ExecContext(ctx, query, userID, entryID)
	if err != nil {
		return err
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}

	if rowsAffected == 0 {
		return ErrEntryNotFound
	}

	return nil
}
