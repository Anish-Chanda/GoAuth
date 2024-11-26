package models

import "time"

type User struct {
	Id              string    `json:"id"`
	Email           string    `json:"email"`
	AuthMethod      string    `json:"auth_method"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`

	// Relationships, possibly null based on AuthMethdo
	PasswordCreds *PasswordCreds `json:"password_creds,omitempty"`
	RefreshTokens *RefreshToken  `json:"refresh_tokens,omitempty"`
}

// PasswordCreds stores password-based authentication details
type PasswordCreds struct {
	CredentialID string    `json:"credential_id"`
	UserID       string    `json:"user_id"`
	PasswordHash string    `json:"password_hash"`
	PasswordSalt string    `json:"password_salt"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// RefreshToken represents a refresh token for session management
type RefreshToken struct {
	TokenID   string    `json:"token_id"`
	UserID    string    `json:"user_id"`
	Token     string    `json:"token"`
	Revoked   bool      `json:"revoked"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
	LastUsed  time.Time `json:"last_used"`
}
