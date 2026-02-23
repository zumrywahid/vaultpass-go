CREATE TABLE IF NOT EXISTS vault_entries (
    id             BIGINT AUTO_INCREMENT PRIMARY KEY,
    user_id        BIGINT NOT NULL,
    entry_id       VARCHAR(36) NOT NULL,
    encrypted_data MEDIUMBLOB NOT NULL,
    version        INT NOT NULL DEFAULT 1,
    created_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    deleted        BOOLEAN NOT NULL DEFAULT FALSE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE INDEX idx_user_entry (user_id, entry_id),
    INDEX idx_user_updated (user_id, updated_at),
    INDEX idx_user_deleted (user_id, deleted)
);
