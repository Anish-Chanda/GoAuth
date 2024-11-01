package db

import (
	"context"
	"fmt"

	"github.com/anish-chanda/goauth/internal/models"
)

type Database interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	Exec(ctx context.Context, query string) error
	GetSchemaVersion(ctx context.Context) (int, error)
}

func EnsureSchemaVersionTable( db *Database) error {
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