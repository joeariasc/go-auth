package token

import (
	"errors"
	"fmt"
	"time"

	"github.com/joeariasc/go-auth/internal/db"
	"github.com/joeariasc/go-auth/internal/models"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrInvalidToken       = errors.New("invalid token")
	ErrTokenExpired       = errors.New("token is expired")
	ErrInvalidFingerprint = errors.New("invalid fingerprint")
	ErrInvalidClaims      = errors.New("invalid claims")
)

type Manager struct {
	Conn          *db.Connection
	TokenDuration time.Duration
}

type Params struct {
	Username    string
	Fingerprint string
	ClientType  models.ClientType
	Secret      []byte
}

type ManagerConfig struct {
	Conn          *db.Connection
	TokenDuration time.Duration
}

func NewManager(config ManagerConfig) *Manager {
	return &Manager{
		Conn:          config.Conn,
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
	tokenString, err := token.SignedString(params.Secret)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

func (m *Manager) VerifyToken(tokenString, currentFingerprint string) (*models.UserClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())

	token, _ := parser.ParseWithClaims(tokenString, &models.UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		return nil, nil // We'll verify later with the correct secret
	})

	// Extract preliminary claims to get the user ID
	prelimClaims, ok := token.Claims.(*models.UserClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	// Get user's secret from database
	user, err := m.Conn.GetUser(prelimClaims.Username)
	if err != nil {
		return nil, ErrInvalidToken
	}

	// Now parse and validate with the correct user secret
	validToken, err := jwt.ParseWithClaims(tokenString, &models.UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(user.Secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrTokenExpired
		}
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !validToken.Valid {
		return nil, ErrInvalidToken
	}

	claims, ok := validToken.Claims.(*models.UserClaims)
	if !ok {
		return nil, ErrInvalidClaims
	}

	// Verify fingerprint
	if claims.Fingerprint != currentFingerprint {
		return nil, ErrInvalidFingerprint
	}

	return claims, nil
}
