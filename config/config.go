// Package config provides configuration structures and defaults for GoAuth.
package config

// Config holds the main configuration settings for the GoAuth.
// It includes JWT settings, token lifetimes, database configuration,
// and password policy settings.
type Config struct {
	// JWTSecret is the secret key used for signing JSON Web Tokens. This is not
	// set by in the DefaultConfig
	JWTSecret string
	// AccessTokenTTL specifies the lifetime of access tokens in minutes
	AccessTokenTTL int
	// RefreshTokenTTL specifies the lifetime of refresh tokens in minutes
	RefreshTokenTTL int
	// DB holds the database-specific configuration
	DB DatabaseConfig
	// PasswordConfig holds the password policy and hashing settings
	PasswordConfig PasswordConfig
}

type DatabaseConfig struct {
	Driver string
}

// PasswordConfig defines password policy and hashing parameters.
type PasswordConfig struct {
	// MinLength specifies the minimum allowed password length
	MinLength int
	// MaxLength specifies the maximum allowed password length
	MaxLength int
	// HashSaltLength specifies the length of the salt used in password hashing
	HashSaltLength int
	// HashAlgorithm specifies the hashing algorithm (currently supports: argon2)
	HashAlgorithm string
	// Argon2Iterations specifies the number of iterations for Argon2 hashing
	Argon2Iterations uint32
	// Argon2Memory specifies the memory size in KB for Argon2 hashing
	Argon2Memory uint32
	// Argon2Threads specifies the number of threads to use for Argon2 hashing
	Argon2Threads uint8
	// Argon2KeyLength specifies the length of the generated hash key
	Argon2KeyLength uint32
}

// DefaultConfig returns a new Config instance initialized with recommended default values.
// Resource: OWASP Password storage cheatsheet (https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
// It sets up secure defaults for password policies, token lifetimes, and database configur
func DefaultConfig() *Config {
	return &Config{
		AccessTokenTTL:  15,    // 15 minutes
		RefreshTokenTTL: 10080, // 7 days
		PasswordConfig: PasswordConfig{
			MinLength:        12,
			MaxLength:        64,
			HashSaltLength:   16,
			HashAlgorithm:    "argon2",
			Argon2Iterations: 2,
			Argon2Memory:     19 * 1024, // 19MB
			Argon2Threads:    1,
			Argon2KeyLength:  32,
		},
		// SQLite3 is used as the default database
		DB: DatabaseConfig{
			Driver: "sqlite3",
		},
	}
}
