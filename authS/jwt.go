package auths

import (
	"time"

	"github.com/anish-chanda/goauth/config"
	"github.com/golang-jwt/jwt/v4"
)

// TODO: update claims
func (s *AuthService) generateAccessToken(c *config.Config, userId string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userId,
		"exp":     time.Now().Add(time.Duration(c.AccessTokenTTL) * time.Minute).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(c.JWTSecret))
}

func (s *AuthService) generateRefreshToken(c *config.Config, userId string) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "goauth",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(c.RefreshTokenTTL) * time.Minute)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		Subject:   userId,
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(c.JWTSecret))
}
