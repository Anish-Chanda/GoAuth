package utils

import (
	"fmt"
	"regexp"

	"github.com/anish-chanda/goauth/config"
	"github.com/google/uuid"
)

// ValidateEmailAndPassword performs syntactic validation of email and password inputs
// following OWASP guidelines for syntactic email validation (https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html#syntactic-validation).
func ValidateEmailAndPassword(c *config.Config, email, password string) error {

	if len(email) > 254 {
		return fmt.Errorf("email exceeds max length")
	}

	// RFC 5322 compliant email regex
	re := regexp.MustCompile(`^[A-Za-z0-9._%+\-]{1,63}@[A-Za-z0-9.-]+$`)
	if !re.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}

	if len(password) < c.PasswordConfig.MinLength {
		return fmt.Errorf("password is too short")
	}
	if len(password) > c.PasswordConfig.MaxLength {
		return fmt.Errorf("password is too long")
	}
	return nil
}

func GenerateID() string {
	return uuid.New().String()
}
