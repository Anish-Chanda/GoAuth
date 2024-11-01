package db

import (
    "context"
    "database/sql"
	"fmt"
    
    "github.com/anish-chanda/goauth/db"
	_ "github.com/mattn/go-sqlite3"
    "github.com/anish-chanda/goauth/internal/models"
)


type SQLite3DB struct {
    conn *sql.DB
}

func NewSQLite3DB(db *sql.DB) db.Database {
	return &SQLite3DB{conn: db}
}

func (s *SQLite3DB) CreateUser(ctx context.Context, user *models.User) error {
	return nil
}

func (s *SQLite3DB) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return nil, nil
}

func (s *SQLite3DB) Exec(ctx context.Context, query string) error {
	_, err := s.conn.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("could not exec query: %w", err)
	}
	return nil
}

func (s *SQLite3DB) GetSchemaVersion(ctx context.Context) (int, error) {
	row := s.conn.QueryRowContext(ctx, `SELECT version FROM schema_version ORDER BY version DESC LIMIT 1`)
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