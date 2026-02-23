package model

import "time"

// VaultEntry represents an encrypted vault entry in the database.
type VaultEntry struct {
	ID            int64
	UserID        int64
	EntryID       string
	EncryptedData []byte
	Version       int
	CreatedAt     time.Time
	UpdatedAt     time.Time
	Deleted       bool
}

// VaultEntryRequest represents a single vault entry in a sync upload.
type VaultEntryRequest struct {
	EntryID       string `json:"entry_id"`
	EncryptedData string `json:"encrypted_data"` // base64 encoded
	Version       int    `json:"version"`
	Deleted       bool   `json:"deleted"`
}

// VaultEntryResponse represents a single vault entry in a sync download.
type VaultEntryResponse struct {
	EntryID       string    `json:"entry_id"`
	EncryptedData string    `json:"encrypted_data"` // base64 encoded
	Version       int       `json:"version"`
	UpdatedAt     time.Time `json:"updated_at"`
	Deleted       bool      `json:"deleted"`
}

// SyncRequest represents a client sync request with optional last sync timestamp.
type SyncRequest struct {
	LastSyncedAt *time.Time          `json:"last_synced_at"`
	Entries      []VaultEntryRequest `json:"entries"`
}

// SyncResponse represents a server sync response with changed entries.
type SyncResponse struct {
	SyncedAt time.Time            `json:"synced_at"`
	Entries  []VaultEntryResponse `json:"entries"`
	Skipped  int                  `json:"skipped,omitempty"`
}
