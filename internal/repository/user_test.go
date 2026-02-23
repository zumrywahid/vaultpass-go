package repository

import (
	"testing"
)

func TestNewUserRepository(t *testing.T) {
	repo := NewUserRepository(nil)
	if repo == nil {
		t.Fatal("expected non-nil UserRepository")
	}
	if repo.db != nil {
		t.Fatal("expected nil db when constructed with nil")
	}
}

func TestSentinelErrors(t *testing.T) {
	if ErrUserNotFound == nil {
		t.Fatal("ErrUserNotFound should not be nil")
	}
	if ErrDuplicateEmail == nil {
		t.Fatal("ErrDuplicateEmail should not be nil")
	}
	if ErrUserNotFound.Error() != "user not found" {
		t.Fatalf("unexpected error message: %s", ErrUserNotFound.Error())
	}
	if ErrDuplicateEmail.Error() != "email already exists" {
		t.Fatalf("unexpected error message: %s", ErrDuplicateEmail.Error())
	}
}

func TestIsDuplicateEntryError(t *testing.T) {
	if isDuplicateEntryError(nil) {
		t.Fatal("nil error should not be a duplicate entry error")
	}
	if isDuplicateEntryError(ErrUserNotFound) {
		t.Fatal("ErrUserNotFound should not be a duplicate entry error")
	}
}
