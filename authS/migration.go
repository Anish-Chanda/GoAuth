package auths

import (
	"context"
	"fmt"

	"github.com/anish-chanda/goauth/db"
	sql3 "github.com/anish-chanda/goauth/db/sqlite3"
)

func (s *AuthService) runMigrations() error {
	if err := db.EnsureSchemaVersionTable(&s.Db); err != nil {
		return err
	}

	// get schema version
	currentVersion, err := db.GetSchemaVersion(&s.Db)
	if err != nil {
		return fmt.Errorf("could not get current schema version: %w", err)
	}
	fmt.Println("current schema version: ", currentVersion)

	// handle migrations based on current schema version
	migrations := []struct {
		Version  int
		Migrator func() error
	}{
		{
			Version: 1, Migrator: s.migrateToV1,
		},
	}

	for _, m := range migrations {
		if currentVersion < m.Version {
			// run migration

			if err := m.Migrator(); err != nil {
				return fmt.Errorf("could not run migration to version %d: %w", m.Version, err)
			}

			fmt.Printf("migration to version %d successful\n", m.Version)
		}
	}

	return nil
}

func (s *AuthService) migrateToV1() error {
	// Start transaction for atomic migration
	// TODO: Add support for other db types
	sqliteDB, ok := s.Db.(*sql3.SQLite3DB)
	if !ok {
		return fmt.Errorf("database is not a SQLite3 database")
	}

	tx, err := sqliteDB.Conn.Begin()
	if err != nil {
		return fmt.Errorf("could not begin transaction: %w", err)
	}

	// Defer rollback - will be ignored if transaction is committed
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	const script = `
		CREATE TABLE Users (
			id UUID PRIMARY KEY,
			email VARCHAR(255) NOT NULL,
			auth_method VARCHAR(30) NOT NULL,
			is_email_verified BOOLEAN NOT NULL DEFAULT FALSE,
			is_active BOOLEAN NOT NULL DEFAULT TRUE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
		-- stores password details for users who signup with emailpass method
		CREATE TABLE Password_Creds (
			credential_id UUID PRIMARY KEY,
			user_id UUID REFERENCES Users(id) ON DELETE CASCADE,
			password_hash TEXT NOT NULL,
			password_salt TEXT NOT NULL,
			created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
			updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
		);

		-- table used to stoer refresh tokens
		CREATE TABLE Refresh_Tokens (
			token_id UUID PRIMARY KEY,
			user_id UUID REFERENCES Users(id) ON DELETE CASCADE,
			token TEXT NOT NULL,
			revoked BOOLEAN NOT NULL DEFAULT FALSE,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			last_used TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
    `

	fmt.Println("running migration to version 1")

	// Execute migration within transaction
	if _, err := tx.ExecContext(context.Background(), script); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	// Update schema version within same transaction
	if _, err := tx.ExecContext(context.Background(),
		"INSERT INTO schema_version (version) VALUES (?)", 1); err != nil {
		return fmt.Errorf("could not update schema version: %w", err)
	}

	// Commit transaction
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("could not commit migration transaction: %w", err)
	}
	tx = nil // Prevent rollback after successful commit

	return nil
}
