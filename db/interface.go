package db

import (
	"context"
	"fmt"

	"github.com/anish-chanda/goauth/internal/models"
)

type Database interface {
	// Read functions
	CheckIfEmailExists(ctx context.Context, email string) (bool, error)
	GetSchemaVersion(ctx context.Context) (int, error)
	IsRefreshTokenRevoked(id string) (bool, error)

	// Write functions
	CreateEmailPassUserWithRefresh(ctx context.Context, user *models.User) error // creates a transaction (if supported) and stroes user, password creds and refresh token. sorry for the long name lol

	Exec(ctx context.Context, query string) error
	Close()
}

func EnsureSchemaVersionTable(db *Database) error {
	fmt.Println("ensuring schema version table")

	query := `
		CREATE TABLE IF NOT EXISTS schema_version (
			version INTEGER PRIMARY KEY
		);
	`

	err := (*db).Exec(context.Background(), query)
	if err != nil {
		return fmt.Errorf("could not create schema version table: %w", err)
	}

	return nil
}

func GetSchemaVersion(db *Database) (int, error) {
	version, err := (*db).GetSchemaVersion(context.Background())
	if err != nil {
		return 0, fmt.Errorf("could not get current schema version: %w", err)
	}

	return version, nil
}
