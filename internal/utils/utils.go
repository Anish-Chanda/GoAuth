package utils

import (
	"fmt"

	"github.com/anish-chanda/goauth/config"
	"github.com/google/uuid"
)

func ValidateEmailAndPassword(c *config.Config, email, password string) error {
	// TODO: validate email

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
