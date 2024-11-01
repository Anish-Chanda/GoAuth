package auths

import (
	"fmt" 
	
	"github.com/anish-chanda/goauth/db"
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
	return nil

	// TODO: handle migrations based on current schema version
}

