package crypto

import (
	"strings"
	"testing"
)

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}

	if hash == "" {
		t.Fatal("HashPassword() returned empty string")
	}

	// Verify PHC format: $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		t.Fatalf("HashPassword() expected 6 parts, got %d: %q", len(parts), hash)
	}
	if parts[1] != "argon2id" {
		t.Errorf("HashPassword() algorithm = %q, want %q", parts[1], "argon2id")
	}
	if parts[2] != "v=19" {
		t.Errorf("HashPassword() version = %q, want %q", parts[2], "v=19")
	}
	if parts[3] != "m=65536,t=3,p=2" {
		t.Errorf("HashPassword() params = %q, want %q", parts[3], "m=65536,t=3,p=2")
	}
}

func TestVerifyPasswordCorrect(t *testing.T) {
	password := "my-secure-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}

	match, err := VerifyPassword(password, hash)
	if err != nil {
		t.Fatalf("VerifyPassword() unexpected error: %v", err)
	}
	if !match {
		t.Error("VerifyPassword() returned false for correct password")
	}
}

func TestVerifyPasswordWrong(t *testing.T) {
	hash, err := HashPassword("correct-password")
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}

	match, err := VerifyPassword("wrong-password", hash)
	if err != nil {
		t.Fatalf("VerifyPassword() unexpected error: %v", err)
	}
	if match {
		t.Error("VerifyPassword() returned true for wrong password")
	}
}

func TestHashPasswordProducesDifferentHashes(t *testing.T) {
	password := "same-password"

	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword() unexpected error: %v", err)
	}

	if hash1 == hash2 {
		t.Error("HashPassword() produced identical hashes for same password (salt should differ)")
	}
}

func TestVerifyPasswordInvalidHash(t *testing.T) {
	_, err := VerifyPassword("password", "invalid-hash-format")
	if err == nil {
		t.Error("VerifyPassword() expected error for invalid hash format")
	}
}
