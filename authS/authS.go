package auths

import (
	"crypto/rand"
	"encoding/json"
	"net/http"
	"time"

	"github.com/anish-chanda/goauth/config"
	"github.com/anish-chanda/goauth/db"
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

func NewAuthService(c *config.Config, db db.Database) (*AuthService, error) {
	service := &AuthService{
		Config: c,
		Db:     db,
	}

	if err := service.runMigrations(); err != nil {
		return nil, err
	}
	return service, nil
}

func (s *AuthService) EmailSignup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
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

	// check if email already exists
	isEmailused, err := s.Db.CheckIfEmailExists(ctx, req.Email)
	if err != nil {
		http.Error(w, "could not check if email exists", http.StatusInternalServerError)
		return
	}
	if isEmailused {
		http.Error(w, EmailExists, http.StatusConflict)
		return
	}

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

	user_id := generateID()
	now := time.Now()
	//genearte tokens
	accessToken, err := s.generateAccessToken(s.Config, user_id, now)
	if err != nil {
		http.Error(w, "could not generate access token", http.StatusInternalServerError)
		return
	}

	// TODO: configure refresh token usage from confgis
	refreshToken, err := s.generateRefreshToken(s.Config, user_id, now)
	if err != nil {
		http.Error(w, "could not generate refresh token", http.StatusInternalServerError)
		return
	}

	// Create user
	user := &models.User{
		Id:              user_id, // TODO: optional pass id gen form configs
		Email:           req.Email,
		AuthMethod:      EmailPass,
		IsEmailVerified: false,
		IsActive:        true, // TODO: let this be configurable
		CreatedAt:       now,
		UpdatedAt:       now,
		PasswordCreds: &models.PasswordCreds{
			CredentialID: generateID(),
			UserID:       user_id,
			PasswordHash: string(hash),
			PasswordSalt: string(salt),
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		RefreshTokens: &models.RefreshToken{
			TokenID:   generateID(),
			UserID:    user_id,
			Token:     refreshToken,
			Revoked:   false,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Duration(s.Config.RefreshTokenTTL)),
			LastUsed:  now, // TODO: should this be now?
		},
	}

	// add user to db
	err = s.Db.CreateEmailPassUserWithRefresh(ctx, user)
	if err != nil {
		http.Error(w, "could not create user", http.StatusInternalServerError)
		return
	}

	// Return tokens to the client
	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}
