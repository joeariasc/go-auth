package models_test

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestUserClaims(t *testing.T) {
	// Test secret key - in real tests, this should be loaded from environment/config
	secretKey := []byte("test-secret-key")

	tests := []struct {
		name        string
		claims      models.UserClaims
		validateFn  func(*testing.T, string)
		expectError bool
	}{
		{
			name: "Valid Claims",
			claims: models.UserClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now()),
					NotBefore: jwt.NewNumericDate(time.Now()),
					Issuer:    "test-issuer",
					Subject:   "test-subject",
					ID:        "test-id",
					Audience:  []string{"test-audience"},
				},
				Username:    "testuser",
				Fingerprint: "abc123",
				ClientType:  "web",
			},
			validateFn: func(t *testing.T, tokenString string) {
				token, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
					return secretKey, nil
				})

				assert.NoError(t, err)
				assert.True(t, token.Valid)

				if claims, ok := token.Claims.(*models.UserClaims); ok {
					assert.Equal(t, "testuser", claims.Username)
					assert.Equal(t, "abc123", claims.Fingerprint)
					assert.Equal(t, "web", claims.ClientType)
					assert.Equal(t, "test-issuer", claims.Issuer)
					assert.Equal(t, "test-subject", claims.Subject)
					assert.Equal(t, "test-id", claims.ID)
					assert.Contains(t, claims.Audience, "test-audience")
				} else {
					t.Error("Failed to cast claims to UserClaims")
				}
			},
			expectError: false,
		},
		{
			name: "Expired Token",
			claims: models.UserClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(-24 * time.Hour)), // Expired
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(-48 * time.Hour)),
				},
				Username:    "testuser",
				Fingerprint: "abc123",
				ClientType:  "web",
			},
			validateFn: func(t *testing.T, tokenString string) {
				_, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
					return secretKey, nil
				})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "token is expired")
			},
			expectError: false, // We expect token creation to succeed but validation to fail
		},
		{
			name: "Future Token",
			claims: models.UserClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					ExpiresAt: jwt.NewNumericDate(time.Now().Add(48 * time.Hour)),
					IssuedAt:  jwt.NewNumericDate(time.Now().Add(24 * time.Hour)), // Future time
					NotBefore: jwt.NewNumericDate(time.Now()),
				},
				Username:    "testuser",
				Fingerprint: "abc123",
				ClientType:  "web",
			},
			validateFn: func(t *testing.T, tokenString string) {
				parser := jwt.NewParser(
					jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
					jwt.WithIssuedAt(),
				)
				_, err := parser.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
					return secretKey, nil
				})
				assert.Error(t, err)
				assert.Contains(t, err.Error(), "token used before issued")
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create token
			token := jwt.NewWithClaims(jwt.SigningMethodHS256, tt.claims)
			tokenString, err := token.SignedString(secretKey)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, tokenString)

			// Run validation function if provided
			if tt.validateFn != nil {
				tt.validateFn(t, tokenString)
			}
		})
	}
}

// Helper function to validate UserClaims
func validateUserClaims(claims *models.UserClaims) error {
	if claims.Username == "" {
		return fmt.Errorf("username is required")
	}
	if claims.Fingerprint == "" {
		return fmt.Errorf("fingerprint is required")
	}
	if claims.ClientType != "web" && claims.ClientType != "android" && claims.ClientType != "ios" {
		return fmt.Errorf("invalid client type")
	}
	return nil
}
