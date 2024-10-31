package auths

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"time"

	"github.com/anish-chanda/goauth/config"
	"github.com/anish-chanda/goauth/internal/db"
	"github.com/anish-chanda/goauth/internal/models"
)

// error messages
const (
	InvalidReqBody     = "invalid request body"
	InvalidCredentials = "invalid credentials"
	ErrInvalidPassword = "invalid password"
	EmailExists        = "email already exists"
	MissingFields      = "missing required fields"
)

// Auth Methds
const (
	EmailPass = "emailpassword"
)

type AuthService struct {
	Config *config.Config
	Db     db.Database
}

func (s *AuthService) EmailSignup(w http.ResponseWriter, r *http.Request) {
	// ctx := r.Context()
	// extract and validate req body
	var req models.EmailSignupRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, InvalidReqBody, http.StatusBadRequest)
		return
	}

	// check for missing fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, MissingFields, http.StatusBadRequest)
		return
	}

	// validate email and pass according to config
	if err := validateEmailAndPassword(s.Config, req.Email, req.Password); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// TODO: check if email already exists
	// existingUser, err := s.Db.GetUserByEmail(ctx, req.Email)
	// if err != nil {
	// 	// TODO: log
	// 	http.Error(w, "something went wrong", http.StatusInternalServerError)
	// 	return
	// }
	// if existingUser != nil {
	// 	http.Error(w, EmailExists, http.StatusBadRequest)
	// 	return
	// }

	// generate salt
	salt := make([]byte, s.Config.PasswordConfig.HashSaltLength)
	if _, err := rand.Read(salt); err != nil {
		http.Error(w, "could not generate salt", http.StatusInternalServerError)
		return
	}

	//hash password
	hasher, err := CreateHasher(&s.Config.PasswordConfig)
	if err != nil {
		http.Error(w, "could not hash password", http.StatusInternalServerError)
		return
	}
	hash, err := hasher.HashPassword([]byte(req.Password), salt)
	if err != nil {
		http.Error(w, "could not hash password", http.StatusInternalServerError)
		return
	}

	//TODO: Create user
	user := &models.User{
		User_id:    generateID(), // TODO: optional pass form configs
		Email:      req.Email,
		PassHash:   string(hash),
		Salt:       string(salt),
		AuthMethod: EmailPass,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	// TODO: add user to db

	//genearte tokens
	accessToken, err := s.generateAccessToken(s.Config, user.User_id)
	if err != nil {
		http.Error(w, "could not generate access token", http.StatusInternalServerError)
		return
	}

	refreshToken, err := s.generateRefreshToken(s.Config, user.User_id)
	if err != nil {
		http.Error(w, "could not generate refresh token", http.StatusInternalServerError)
		return
	}

	// Return tokens to the client
	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}
