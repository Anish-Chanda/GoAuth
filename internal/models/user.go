package models

import "time"

type User struct {
	User_id    string    `json:"user_id"`
	Email      string    `json:"email"`
	PassHash   string    `json:"password_hash"`
	Salt       string    `json:"salt"`
	AuthMethod string    `json:"auth_method"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}
