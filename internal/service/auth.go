package service

import (
	"context"
	"errors"
	"time"

	"github.com/vaultpass/vaultpass-go/internal/crypto"
	"github.com/vaultpass/vaultpass-go/internal/model"
	"github.com/vaultpass/vaultpass-go/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrEmailRequired      = errors.New("email is required")
	ErrPasswordRequired   = errors.New("password is required")
	ErrEmailTaken         = errors.New("email already taken")
)

// AuthService handles authentication business logic.
type AuthService struct {
	repo      *repository.UserRepository
	jwtSecret string
	jwtExpiry time.Duration
}

// NewAuthService creates a new AuthService.
func NewAuthService(repo *repository.UserRepository, secret string, expiry time.Duration) *AuthService {
	return &AuthService{
		repo:      repo,
		jwtSecret: secret,
		jwtExpiry: expiry,
	}
}

// Register creates a new user account and returns an auth token.
func (s *AuthService) Register(ctx context.Context, req model.CreateUserRequest) (model.AuthResponse, error) {
	if req.Email == "" {
		return model.AuthResponse{}, ErrEmailRequired
	}
	if req.Password == "" {
		return model.AuthResponse{}, ErrPasswordRequired
	}

	hash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return model.AuthResponse{}, err
	}

	user := &model.User{
		Email:    req.Email,
		AuthHash: hash,
	}

	if err := s.repo.Create(ctx, user); err != nil {
		if errors.Is(err, repository.ErrDuplicateEmail) {
			return model.AuthResponse{}, ErrEmailTaken
		}
		return model.AuthResponse{}, err
	}

	token, err := crypto.GenerateToken(user.ID, s.jwtSecret, s.jwtExpiry)
	if err != nil {
		return model.AuthResponse{}, err
	}

	return model.AuthResponse{
		Token: token,
		User: model.UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		},
	}, nil
}

// Login authenticates a user and returns an auth token.
func (s *AuthService) Login(ctx context.Context, req model.LoginRequest) (model.AuthResponse, error) {
	user, err := s.repo.GetByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, repository.ErrUserNotFound) {
			return model.AuthResponse{}, ErrInvalidCredentials
		}
		return model.AuthResponse{}, err
	}

	match, err := crypto.VerifyPassword(req.Password, user.AuthHash)
	if err != nil {
		return model.AuthResponse{}, err
	}
	if !match {
		return model.AuthResponse{}, ErrInvalidCredentials
	}

	token, err := crypto.GenerateToken(user.ID, s.jwtSecret, s.jwtExpiry)
	if err != nil {
		return model.AuthResponse{}, err
	}

	return model.AuthResponse{
		Token: token,
		User: model.UserResponse{
			ID:        user.ID,
			Email:     user.Email,
			CreatedAt: user.CreatedAt,
		},
	}, nil
}

// GetUser retrieves a user by ID and returns safe user data.
func (s *AuthService) GetUser(ctx context.Context, userID int64) (model.UserResponse, error) {
	user, err := s.repo.GetByID(ctx, userID)
	if err != nil {
		return model.UserResponse{}, err
	}

	return model.UserResponse{
		ID:        user.ID,
		Email:     user.Email,
		CreatedAt: user.CreatedAt,
	}, nil
}
