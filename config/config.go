package config

type Config struct {
	JWTSecret       string
	AccessTokenTTL  int // in minutes
	RefreshTokenTTL int // in minutes
	DB              DatabaseConfig
	PasswordConfig  PasswordConfig
}

type DatabaseConfig struct {
	Driver string
}

type PasswordConfig struct {
	MinLength        int
	MaxLength        int
	HashSaltLength   int
	HashAlgorithm    string //argon2id
	Argon2Iterations uint32
	Argon2Memory     uint32
	Argon2Threads    uint8
	Argon2KeyLength  uint32
}

func DefaultConfig() *Config {
	return &Config{
		AccessTokenTTL:  15,    // 15 minutes
		RefreshTokenTTL: 10080, // 7 days
		PasswordConfig: PasswordConfig{
			MinLength:        12,
			MaxLength:        64,
			HashSaltLength:   16,
			HashAlgorithm:    "argon2",
			Argon2Iterations: 4,
			Argon2Memory:     64 * 1024,
			Argon2Threads:    4,
			Argon2KeyLength:  32,
		},
		// SQLite3 is used as the default database
		DB: DatabaseConfig{
			Driver: "sqlite3",
		},
	}
}
