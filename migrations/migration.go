package migrations

import (
	"embed"
	"fmt"

	// auths "github.com/anish-chanda/goauth/authS"
	"github.com/anish-chanda/goauth/db"
	sql3 "github.com/anish-chanda/goauth/db/sqlite3"
	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/sqlite3"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed sqlite3/*.sql
var migrationFiles embed.FS

func RunMigrations(db db.Database) error {
	sqliteDB, ok := db.(*sql3.SQLite3DB)
	if !ok {
		return fmt.Errorf("database is not a SQLite3 database")
	}

	d, err := iofs.New(migrationFiles, "sqlite3")
	if err != nil {
		return fmt.Errorf("failed to create migration source: %w", err)
	}

	dbDriver, err := sqlite3.WithInstance(sqliteDB.Conn, &sqlite3.Config{})
	if err != nil {
		return fmt.Errorf("could not create database driver: %w", err)
	}

	m, err := migrate.NewWithInstance(
		"iofs", d,
		"sqlite3", dbDriver,
	)
	if err != nil {
		return fmt.Errorf("could not create migrate instance: %w", err)
	}

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("could not run migrations: %w", err)
	}

	return nil
}
