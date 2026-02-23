package model

import "time"

// User represents a user in the database.
type User struct {
	ID        int64
	Email     string
	AuthHash  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// CreateUserRequest represents a user registration request.
type CreateUserRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// LoginRequest represents a user login request.
type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// AuthResponse represents an authentication response with a JWT token and user info.
type AuthResponse struct {
	Token string       `json:"token"`
	User  UserResponse `json:"user"`
}

// UserResponse represents user data safe for API responses (no sensitive fields).
type UserResponse struct {
	ID        int64     `json:"id"`
	Email     string    `json:"email"`
	CreatedAt time.Time `json:"created_at"`
}
