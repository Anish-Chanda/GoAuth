package db

import (
	"context"

	"github.com/anish-chanda/goauth/internal/models"
)

type Database interface {
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
}
