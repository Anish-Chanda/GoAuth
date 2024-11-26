package auths

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/anish-chanda/goauth/config"
	"github.com/anish-chanda/goauth/internal/models"
	"github.com/anish-chanda/goauth/internal/utils"
)

type MockDatabase struct {
	CheckIfEmailExistsFunc             func(ctx context.Context, email string) (bool, error)
	CreateEmailPassUserWithRefreshFunc func(ctx context.Context, user *models.User) error
	IsRefreshTokenRevokedFunc          func(id string) (bool, error)
	UpdateRefreshTokLastUsedFunc       func(ctx context.Context, id string, now time.Time) error
	StoreRefreshTokenFunc              func(context.Context, models.RefreshToken) error
	GetPassUserByEmailFunc             func(ctx context.Context, email string) (models.User, error)
	GetSchemaVersionFunc               func(ctx context.Context) (int, error)
	ExecFunc                           func(ctx context.Context, query string) error
	CloseFunc                          func()
}

func (m *MockDatabase) CheckIfEmailExists(ctx context.Context, email string) (bool, error) {
	if m.CheckIfEmailExistsFunc != nil {
		return m.CheckIfEmailExistsFunc(ctx, email)
	}
	return false, nil
}

func (m *MockDatabase) CreateEmailPassUserWithRefresh(ctx context.Context, user *models.User) error {
	if m.CreateEmailPassUserWithRefreshFunc != nil {
		return m.CreateEmailPassUserWithRefreshFunc(ctx, user)
	}
	return nil
}

func (m *MockDatabase) IsRefreshTokenRevoked(id string) (bool, error) {
	if m.IsRefreshTokenRevokedFunc != nil {
		return m.IsRefreshTokenRevokedFunc(id)
	}
	return false, nil
}

func (m *MockDatabase) UpdateRefreshTokLastUsed(ctx context.Context, id string, now time.Time) error {
	if m.UpdateRefreshTokLastUsedFunc != nil {
		return m.UpdateRefreshTokLastUsedFunc(ctx, id, now)
	}
	return nil
}

func (m *MockDatabase) StoreRefreshToken(ctx context.Context, token models.RefreshToken) error {
	if m.StoreRefreshTokenFunc != nil {
		return m.StoreRefreshTokenFunc(ctx, token)
	}
	return nil
}

func (m *MockDatabase) GetPassUserByEmail(ctx context.Context, email string) (models.User, error) {
	if m.GetPassUserByEmailFunc != nil {
		return m.GetPassUserByEmailFunc(ctx, email)
	}
	return models.User{}, nil
}

func (m *MockDatabase) GetSchemaVersion(ctx context.Context) (int, error) {
	if m.GetSchemaVersionFunc != nil {
		return m.GetSchemaVersionFunc(ctx)
	}
	return 0, nil
}

func (m *MockDatabase) Exec(ctx context.Context, query string) error {
	if m.ExecFunc != nil {
		return m.ExecFunc(ctx, query)
	}
	return nil
}

func (m *MockDatabase) Close() {
	if m.CloseFunc != nil {
		m.CloseFunc()
	}
}

func TestEmailSignup(t *testing.T) {
	tests := []struct {
		testName      string
		requestBody   models.EmailSignupRequest
		expectedCode  int
		expectedError string
		mockDb        *MockDatabase
	}{
		{
			testName: "valid request",
			requestBody: models.EmailSignupRequest{
				Email:    "test@test.com",
				Password: "Test@1234",
			},
			expectedCode: http.StatusCreated,
			mockDb: &MockDatabase{
				CheckIfEmailExistsFunc: func(ctx context.Context, email string) (bool, error) {
					return false, nil
				},
				CreateEmailPassUserWithRefreshFunc: func(ctx context.Context, user *models.User) error {
					return nil
				},
			},
		},
		{
			testName: "missing fields",
			requestBody: models.EmailSignupRequest{
				Email:    "",
				Password: "",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: MissingFields + "\n",
		},
		{
			testName: "short password",
			requestBody: models.EmailSignupRequest{
				Email:    "test@test.com",
				Password: "hi",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: "password is too short" + "\n",
		},
		{
			testName: "email exists",
			requestBody: models.EmailSignupRequest{
				Email:    "exists@test.com",
				Password: "Test@1234!",
			},
			expectedCode:  http.StatusConflict,
			expectedError: EmailExists + "\n",
			mockDb: &MockDatabase{
				CheckIfEmailExistsFunc: func(ctx context.Context, email string) (bool, error) {
					return true, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.testName, func(t *testing.T) {
			// Prepare request body
			var req *http.Request
			if tt.testName == "invalid request body" {
				req = httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader([]byte("invalid json")))
			} else {
				body, err := json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
				req = httptest.NewRequest(http.MethodPost, "/signup", bytes.NewReader(body))
			}
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Create AuthService with mock db and config
			cfg := &config.Config{
				PasswordConfig: config.PasswordConfig{
					MinLength:        6,
					MaxLength:        64,
					HashSaltLength:   16,
					HashAlgorithm:    "argon2",
					Argon2Iterations: 4,
					Argon2Memory:     64 * 1024,
					Argon2Threads:    4,
					Argon2KeyLength:  32,
				},
				JWTSecret:       "secret",
				AccessTokenTTL:  15,
				RefreshTokenTTL: 1440,
			}

			authService := &AuthService{
				Config: cfg,
				Db:     tt.mockDb,
			}

			// Call the handler
			authService.EmailSignup(w, req)

			// Check the response
			resp := w.Result()
			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedCode, resp.StatusCode)
			}

			if tt.expectedError != "" {
				// Read the response body and check the error message
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				resp.Body.Close()
				if string(body) != tt.expectedError {
					t.Errorf("Expected error message '%s', got '%s'", tt.expectedError, string(body))
				}
			} else {
				// For successful response, we can check the tokens
				var responseData map[string]string
				err := json.NewDecoder(resp.Body).Decode(&responseData)
				if err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}
				// Check that access_token and refresh_token are present
				if _, ok := responseData["access_token"]; !ok {
					t.Errorf("Expected access_token in response")
				}
				if _, ok := responseData["refresh_token"]; !ok {
					t.Errorf("Expected refresh_token in response")
				}
			}
		})
	}
}

func TestEmailLogin(t *testing.T) {
	cfg := &config.Config{
		PasswordConfig: config.PasswordConfig{
			MinLength:        8,
			MaxLength:        64,
			HashSaltLength:   16,
			HashAlgorithm:    "argon2",
			Argon2Iterations: 4,
			Argon2Memory:     64 * 1024,
			Argon2Threads:    4,
			Argon2KeyLength:  32,
		},
		JWTSecret:       "secret",
		AccessTokenTTL:  15,
		RefreshTokenTTL: 1440,
	}
	const testEmail = "test@test.com"

	// create a test hasher to generate valid hashes for few test cases
	hasher, _ := utils.CreateHasher(&cfg.PasswordConfig)
	testPassword := "ValidPassword1!"
	testSalt := []byte("testsalt12345678")
	hash, _ := hasher.HashPassword([]byte(testPassword), testSalt)

	tests := []struct {
		name          string
		requestBody   models.EmailSignupRequest
		expectedCode  int
		expectedError string
		mockDb        *MockDatabase
	}{
		{
			name: "valid login",
			requestBody: models.EmailSignupRequest{
				Email:    testEmail,
				Password: testPassword,
			},
			expectedCode: http.StatusOK,
			mockDb: &MockDatabase{
				GetPassUserByEmailFunc: func(ctx context.Context, email string) (models.User, error) {
					return models.User{
						Id:         "user123",
						Email:      testEmail,
						AuthMethod: EmailPass,
						PasswordCreds: &models.PasswordCreds{
							PasswordHash: string(hash),
							PasswordSalt: string(testSalt),
						},
					}, nil
				},
				StoreRefreshTokenFunc: func(ctx context.Context, token models.RefreshToken) error {
					return nil
				},
			},
		},
		{
			name: "missing fields",
			requestBody: models.EmailSignupRequest{
				Email:    "",
				Password: "",
			},
			expectedCode:  http.StatusBadRequest,
			expectedError: MissingFields + "\n",
		},
		{
			name: "invalid credentials",
			requestBody: models.EmailSignupRequest{
				Email:    testEmail,
				Password: "WrongPassword",
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: InvalidCredentials + "\n",
			mockDb: &MockDatabase{
				GetPassUserByEmailFunc: func(ctx context.Context, email string) (models.User, error) {
					return models.User{
						Id:         "user123",
						Email:      testEmail,
						AuthMethod: EmailPass,
						PasswordCreds: &models.PasswordCreds{
							PasswordHash: string(hash),
							PasswordSalt: string(testSalt),
						},
					}, nil
				},
			},
		},
		{
			name: "user not found",
			requestBody: models.EmailSignupRequest{
				Email:    "nonexistent@test.com",
				Password: testPassword,
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: InvalidCredentials + "\n",
			mockDb: &MockDatabase{
				GetPassUserByEmailFunc: func(ctx context.Context, email string) (models.User, error) {
					return models.User{}, errors.New("user not found")
				},
			},
		},
		{
			name: "invalid auth method",
			requestBody: models.EmailSignupRequest{
				Email:    testEmail,
				Password: testPassword,
			},
			expectedCode:  http.StatusUnauthorized,
			expectedError: InvalidAuthMethod + "\n",
			mockDb: &MockDatabase{
				GetPassUserByEmailFunc: func(ctx context.Context, email string) (models.User, error) {
					return models.User{
						Id:         "user123",
						Email:      testEmail,
						AuthMethod: "oauth",
					}, nil
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Prepare request body
			var req *http.Request
			if tt.name == "invalid request body" {
				req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte("invalid json")))
			} else {
				body, err := json.Marshal(tt.requestBody)
				if err != nil {
					t.Fatalf("Failed to marshal request body: %v", err)
				}
				req = httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body))
			}
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// Create AuthService with mock db and config
			authService := &AuthService{
				Config: cfg,
				Db:     tt.mockDb,
			}

			// Call the handler
			authService.EmailLogin(w, req)

			// Check the response
			resp := w.Result()
			if resp.StatusCode != tt.expectedCode {
				t.Errorf("Expected status code %d, got %d", tt.expectedCode, resp.StatusCode)
			}

			if tt.expectedError != "" {
				// Read the response body and check the error message
				body, err := io.ReadAll(resp.Body)
				if err != nil {
					t.Fatalf("Failed to read response body: %v", err)
				}
				resp.Body.Close()
				if string(body) != tt.expectedError {
					t.Errorf("Expected error message '%s', got '%s'", tt.expectedError, string(body))
				}
			} else {
				// For successful response, we can check the tokens
				var responseData map[string]string
				err := json.NewDecoder(resp.Body).Decode(&responseData)
				if err != nil {
					t.Fatalf("Failed to decode response body: %v", err)
				}
				// Check that access_token and refresh_token are present
				if _, ok := responseData["access_token"]; !ok {
					t.Errorf("Expected access_token in response")
				}
				if _, ok := responseData["refresh_token"]; !ok {
					t.Errorf("Expected refresh_token in response")
				}
			}
		})
	}
}
