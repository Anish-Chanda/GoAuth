package models

type EmailSignupRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}
