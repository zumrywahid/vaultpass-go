package service

import (
	"context"
	"testing"
	"time"

	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/repository"
)

func newTestAuthService() *AuthService {
	return NewAuthService(
		repository.NewUserRepository(nil),
		"test-secret",
		time.Hour,
	)
}

func TestRegister_EmptyEmail(t *testing.T) {
	svc := newTestAuthService()

	_, err := svc.Register(context.Background(), model.CreateUserRequest{
		Email:    "",
		Password: "password123",
	})

	if err != ErrEmailRequired {
		t.Errorf("expected ErrEmailRequired, got %v", err)
	}
}

func TestRegister_EmptyPassword(t *testing.T) {
	svc := newTestAuthService()

	_, err := svc.Register(context.Background(), model.CreateUserRequest{
		Email:    "test@example.com",
		Password: "",
	})

	if err != ErrPasswordRequired {
		t.Errorf("expected ErrPasswordRequired, got %v", err)
	}
}
