package db

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/anish-chanda/goauth/db"
	"github.com/anish-chanda/goauth/internal/models"
	_ "github.com/mattn/go-sqlite3"
)

type SQLite3DB struct {
	Conn *sql.DB
}

func NewSQLite3DB(db *sql.DB) db.Database {
	return &SQLite3DB{Conn: db}
}

func (s *SQLite3DB) CheckIfEmailExists(ctx context.Context, email string) (bool, error) {
	var count int
	row := s.Conn.QueryRowContext(ctx, `SELECT COUNT(1) FROM Users WHERE email = ? LIMIT 1`,
		email)
	if err := row.Scan(&count); err != nil {
		return false, fmt.Errorf("could not check if email exists: %w", err)
	}
	return count > 0, nil
}

func (s *SQLite3DB) Exec(ctx context.Context, query string) error {
	_, err := s.Conn.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("could not exec query: %w", err)
	}
	return nil
}

func (s *SQLite3DB) GetSchemaVersion(ctx context.Context) (int, error) {
	row := s.Conn.QueryRowContext(ctx, `SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`)
	var version int
	err := row.Scan(&version)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil // Return 0 if no rows are found
		}
		return 0, fmt.Errorf("could not get schema version: %w", err)
	}
	return version, nil
}

func (s *SQLite3DB) CreateEmailPassUserWithRefresh(ctx context.Context, user *models.User) error {
	tx, err := s.Conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Insert user
	userQuery := `
        INSERT INTO Users (
            id, email, auth_method, is_email_verified, 
            is_active, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)`

	_, err = tx.ExecContext(ctx, userQuery,
		user.Id,
		user.Email,
		user.AuthMethod,
		user.IsEmailVerified,
		user.IsActive,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("could not create user: %w", err)
	}

	// Insert password credentials
	if user.PasswordCreds != nil {
		credsQuery := `
            INSERT INTO Password_Creds (
                credential_id, user_id, password_hash,
                password_salt, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?)`

		_, err = tx.ExecContext(ctx, credsQuery,
			user.PasswordCreds.CredentialID,
			user.Id,
			user.PasswordCreds.PasswordHash,
			user.PasswordCreds.PasswordSalt,
			user.PasswordCreds.CreatedAt,
			user.PasswordCreds.UpdatedAt,
		)
		if err != nil {
			return fmt.Errorf("could not create password credentials: %w", err)
		}
	}

	// Insert refresh token
	if user.RefreshTokens != nil {
		tokenQuery := `
            INSERT INTO Refresh_Tokens (
                token_id, user_id, token, revoked,
                created_at, expires_at, last_used
            ) VALUES (?, ?, ?, ?, ?, ?, ?)`

		_, err = tx.ExecContext(ctx, tokenQuery,
			user.RefreshTokens.TokenID,
			user.Id,
			user.RefreshTokens.Token,
			user.RefreshTokens.Revoked,
			user.RefreshTokens.CreatedAt,
			user.RefreshTokens.ExpiresAt,
			user.RefreshTokens.LastUsed,
		)
		if err != nil {
			return fmt.Errorf("could not create refresh token: %w", err)
		}
	}

	return tx.Commit()
}

func (s *SQLite3DB) IsRefreshTokenRevoked(id string) (bool, error) {
	var revoked bool
	row := s.Conn.QueryRow(`SELECT revoked FROM Refresh_Tokens WHERE token_id = ? LIMIT 1`, id)
	err := row.Scan(&revoked)

	if err != nil {
		return false, fmt.Errorf("could not check if refresh token is revoked: %w", err)
	}
	return revoked, nil
}

func (s *SQLite3DB) GetPassUserByEmail(ctx context.Context, email string) (models.User, error) {
	var user models.User
	row := s.Conn.QueryRowContext(ctx, `SELECT * FROM Users WHERE email = ? LIMIT 1`, email)
	err := row.Scan(
		&user.Id,
		&user.Email,
		&user.AuthMethod,
		&user.IsEmailVerified,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
	)
	if err != nil {
		return models.User{}, fmt.Errorf("could not get user by email: %w", err)
	}

	user.PasswordCreds = &models.PasswordCreds{}

	// Get password cred
	credsRow := s.Conn.QueryRowContext(ctx, `SELECT * FROM Password_Creds WHERE user_id = ? LIMIT 1`, user.Id)
	err = credsRow.Scan(
		&user.PasswordCreds.CredentialID,
		&user.PasswordCreds.UserID,
		&user.PasswordCreds.PasswordHash,
		&user.PasswordCreds.PasswordSalt,
		&user.PasswordCreds.CreatedAt,
		&user.PasswordCreds.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return models.User{}, fmt.Errorf("no password creds found for user id: %s", user.Id)
		}
		return models.User{}, fmt.Errorf("could not get password creds: %w", err)

	}

	return user, nil
}

func (s *SQLite3DB) StoreRefreshToken(ctx context.Context, token models.RefreshToken) error {
	_, err := s.Conn.ExecContext(ctx, `
		INSERT INTO Refresh_Tokens (
			token_id, user_id, token, revoked,
			created_at, expires_at, last_used
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, token.TokenID, token.UserID, token.Token, token.Revoked, token.CreatedAt, token.ExpiresAt, token.LastUsed)
	if err != nil {
		return fmt.Errorf("could not store refresh token: %w", err)
	}
	return nil
}

func (s *SQLite3DB) UpdateRefreshTokLastUsed(ctx context.Context, id string, now time.Time) error {
	_, err := s.Conn.ExecContext(ctx, `UPDATE Refresh_Tokens SET last_used = ? WHERE token_id = ?`, now, id)
	if err != nil {
		return fmt.Errorf("could not update refresh token last used: %w", err)
	}
	return nil
}

func (s *SQLite3DB) Close() {
	s.Conn.Close()
}
