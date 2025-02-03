package token

import (
	"errors"
	"fmt"
	"github.com/joeariasc/go-auth/internal/models"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token is expired")
	ErrInvalidFingerprint = errors.New("invalid fingerprint")
	ErrInvalidClaims      = errors.New("invalid claims")
)

type Manager struct {
	secretKey     []byte
	TokenDuration time.Duration
}

type Params struct {
	Username    string
	Fingerprint string
	ClientType  models.ClientType
	Secret      string
}

type ManagerConfig struct {
	SecretKey     []byte
	TokenDuration time.Duration
}

func NewManager(config ManagerConfig) *Manager {
	return &Manager{
		secretKey:     config.SecretKey,
		TokenDuration: config.TokenDuration,
	}
}

func (m *Manager) GenerateToken(params Params) (string, error) {
	now := time.Now()

	// Create claims with standard JWT claims and custom fields
	claims := &models.UserClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(now.Add(m.TokenDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(now),
			Subject:   params.Username,
		},
		Username:    params.Username,
		Fingerprint: params.Fingerprint,
		ClientType:  string(params.ClientType),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString(m.secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (m *Manager) VerifyToken(tokenString, currentFingerprint string) (*models.UserClaims, error) {
	// parse and validate token
	token, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return m.secretKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, ErrInvalidToken
	}

	// Extract claims
	claims, ok := token.Claims.(*models.UserClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	// Verify fingerprint
	if claims.Fingerprint != currentFingerprint {
		return nil, ErrInvalidFingerprint
	}

	return claims, nil
}

// RefreshToken creates a new token while validating the old one
func (m *Manager) RefreshToken(oldTokenString, currentFingerprint string) (string, error) {
	// Verify old token first
	claims, err := m.VerifyToken(oldTokenString, currentFingerprint)
	if err != nil {
		if errors.Is(err, ErrTokenExpired) {
			// Optionally allow refresh for recently expired tokens
			claims, err = m.extractExpiredClaims(oldTokenString)
			if err != nil {
				return "", err
			}
		} else {
			return "", err
		}
	}

	params := Params{
		Username:    claims.Username,
		Fingerprint: currentFingerprint,
		ClientType:  models.ClientType(claims.ClientType),
		Secret:      "",
	}

	// Generate new token
	return m.GenerateToken(params)
}

// extractExpiredClaims parses an expired token to extract its claims
func (m *Manager) extractExpiredClaims(tokenString string) (*models.UserClaims, error) {
	// Create parser with ParseOption
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, err := parser.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return m.secretKey, nil
	})

	if err != nil && !errors.Is(err, jwt.ErrTokenExpired) {
		return nil, fmt.Errorf("failed to parse expired token: %w", err)
	}

	claims, ok := token.Claims.(*models.UserClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	// Check if token is too old to refresh (e.g., expired more than 24 hours ago)
	if claims.ExpiresAt.Time.Before(time.Now().Add(-24 * time.Hour)) {
		return nil, fmt.Errorf("token too old to refresh")
	}

	return claims, nil
}

// ValidateFingerprint checks if the current fingerprint matches the one in the token
func (m *Manager) ValidateFingerprint(tokenString, currentFingerprint string) error {
	claims, err := m.extractClaimsWithoutValidation(tokenString)
	if err != nil {
		return err
	}

	if claims.Fingerprint != currentFingerprint {
		return ErrInvalidFingerprint
	}

	return nil
}

// extractClaimsWithoutValidation gets claims without validating the token
func (m *Manager) extractClaimsWithoutValidation(tokenString string) (*models.UserClaims, error) {
	// Create parser with ParseOption
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, err := parser.ParseWithClaims(tokenString, &models.UserClaims{}, func(token *jwt.Token) (interface{}, error) {
		return m.secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	claims, ok := token.Claims.(*models.UserClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	return claims, nil
}
