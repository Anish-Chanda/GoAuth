package auths

import (
	"time"

	"github.com/anish-chanda/goauth/config"
	"github.com/golang-jwt/jwt/v4"
)

func (s *AuthService) generateAccessToken(c *config.Config, userId string, t time.Time) (string, error) {
	claims := jwt.MapClaims{
		// Registered claims
		"iss": "goauth",                                                                 // Issuer
		"sub": userId,                                                                   // Subject (user ID)
		"iat": jwt.NewNumericDate(t),                                                    // Issued At
		"exp": jwt.NewNumericDate(t.Add(time.Duration(c.AccessTokenTTL) * time.Minute)), // Expiry

		// Custom claims
		"type":        "access",  // Token type
		"auth_method": EmailPass, // Authentication method used
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(c.JWTSecret))
}

func (s *AuthService) generateRefreshToken(c *config.Config, userId string, t time.Time) (string, error) {

	claims := jwt.RegisteredClaims{
		Issuer:    "goauth",
		Subject:   userId,
		IssuedAt:  jwt.NewNumericDate(t),
		ExpiresAt: jwt.NewNumericDate(t.Add(time.Duration(c.RefreshTokenTTL) * time.Minute)), // Expiry based on Config.RefreshTokenTTL
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(c.JWTSecret))
}
