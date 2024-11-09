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

func (s *AuthService) generateRefreshToken(userId string, now time.Time, refreshId string) (string, error) {
	refreshDuration := time.Duration(s.Config.RefreshTokenTTL) * time.Minute
	claims := jwt.RegisteredClaims{
		ID:        refreshId,
		Issuer:    "goauth",
		Subject:   userId,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(refreshDuration)), // Expiry based on Config.RefreshTokenTTL
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.Config.JWTSecret))
}
