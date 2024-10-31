package auths

import (
	"errors"

	"github.com/anish-chanda/goauth/config"
	"golang.org/x/crypto/argon2"
)

type PasswordHasher interface {
	HashPassword(password []byte, salt []byte) ([]byte, error)
	VerifyPassword(password []byte, hash []byte, salt []byte) bool
}

type Argon2Hasher struct {
	Config *config.PasswordConfig
}

func (h *Argon2Hasher) HashPassword(password []byte, salt []byte) ([]byte, error) {
	hash := argon2.IDKey(
		password,
		salt,
		h.Config.Argon2Iterations,
		h.Config.Argon2Memory,
		h.Config.Argon2Threads,
		h.Config.Argon2KeyLength,
	)

	return hash, nil
}

func (h *Argon2Hasher) VerifyPassword(password []byte, hash []byte, salt []byte) bool {
	return true
}

func CreateHasher(c *config.PasswordConfig) (PasswordHasher, error) {
	switch c.HashAlgorithm {
	case "argon2":
		return &Argon2Hasher{Config: c}, nil
	default:
		return nil, errors.New("unsupported hashing method")
	}

}
