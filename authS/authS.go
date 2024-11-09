package auths

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/anish-chanda/goauth/config"
	"github.com/anish-chanda/goauth/db"
	"github.com/anish-chanda/goauth/internal/models"
	"github.com/golang-jwt/jwt/v4"
)

// error messages
const (
	InvalidReqBody     = "invalid request body"
	InvalidCredentials = "invalid credentials"
	ErrInvalidPassword = "invalid password"
	EmailExists        = "email already exists"
	MissingFields      = "missing required fields"
	InvalidAuthMethod  = "invalid auth method"
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
	now := time.Now().UTC()
	//genearte tokens
	accessToken, err := s.generateAccessToken(s.Config, user_id, now)
	if err != nil {
		http.Error(w, "could not generate access token", http.StatusInternalServerError)
		return
	}

	// TODO: configure refresh token usage from confgis
	refreshId := generateID()
	refreshToken, err := s.generateRefreshToken(user_id, now, refreshId)
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
			TokenID:   refreshId,
			UserID:    user_id,
			Token:     refreshToken,
			Revoked:   false,
			CreatedAt: now,
			ExpiresAt: now.Add(time.Duration(s.Config.RefreshTokenTTL) * time.Minute),
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

func (s *AuthService) HandleRefresh(w http.ResponseWriter, r *http.Request) {
	// parse refresh token
	var req models.RefreshRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, InvalidReqBody, http.StatusBadRequest)
		return
	}

	//verify refresh token
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(req.RefreshToken, claims, func(token *jwt.Token) (interface{}, error) {
		return []byte(s.Config.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		http.Error(w, "Invalid refresh token", http.StatusUnauthorized)
		return
	}

	//check if token was revoked
	revoked, err := s.Db.IsRefreshTokenRevoked(claims.ID)
	if err != nil || revoked || claims.ExpiresAt.Time.Before(time.Now().UTC()) {
		http.Error(w, "Refresh token is invalid or expired", http.StatusUnauthorized)
		return
	}

	//generate new access token
	accessTok, err := s.generateAccessToken(s.Config, claims.Subject, time.Now().UTC())
	if err != nil {
		http.Error(w, "could not generate access token", http.StatusInternalServerError)
		return
	}

	// Return the new tokens to the client
	response := map[string]string{
		"access_token": accessTok,
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// LoginRequest represents the expected login request body
func (s *AuthService) EmailLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse request body
	var req models.EmailSignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, InvalidReqBody, http.StatusBadRequest)
		return
	}

	// Validate required fields
	if req.Email == "" || req.Password == "" {
		http.Error(w, MissingFields, http.StatusBadRequest)
		return
	}

	fmt.Println("Hereeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")

	// Get user from database
	user, err := s.Db.GetPassUserByEmail(ctx, req.Email)
	if err != nil {
		// generic error message to avoid leaking info
		http.Error(w, InvalidCredentials, http.StatusUnauthorized)
		return
	}

	//verify auth method
	if user.AuthMethod != EmailPass {
		http.Error(w, InvalidAuthMethod, http.StatusUnauthorized)
		return
	}

	// Verify password
	hasher, err := CreateHasher(&s.Config.PasswordConfig)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	if !hasher.VerifyPassword(
		[]byte(req.Password),
		[]byte(user.PasswordCreds.PasswordHash),
		[]byte(user.PasswordCreds.PasswordSalt),
	) {
		http.Error(w, InvalidCredentials, http.StatusUnauthorized)
		return
	}

	// Generate tokens
	now := time.Now().UTC()
	accessToken, err := s.generateAccessToken(s.Config, user.Id, now)
	if err != nil {
		http.Error(w, "Could not generate access token", http.StatusInternalServerError)
		return
	}

	refreshId := generateID()
	refreshToken, err := s.generateRefreshToken(user.Id, now, refreshId)
	if err != nil {
		http.Error(w, "Could not generate refresh token", http.StatusInternalServerError)
		return
	}

	// Store refresh token
	err = s.Db.StoreRefreshToken(ctx, models.RefreshToken{
		TokenID:   refreshId,
		UserID:    user.Id,
		Token:     refreshToken,
		Revoked:   false,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Duration(s.Config.RefreshTokenTTL) * time.Minute),
		LastUsed:  now,
	})
	if err != nil {
		http.Error(w, "Could not store refresh token", http.StatusInternalServerError)
		return
	}

	// Return tokens
	response := map[string]string{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Write(w)
	json.NewEncoder(w).Encode(response)
}
