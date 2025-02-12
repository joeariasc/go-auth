package middleware

import (
	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"github.com/joeariasc/go-auth/internal/auth/token"
)

type Middleware struct {
	fingerprintManager *fingerprint.Manager
	tokenManager       *token.Manager
}

func NewMiddleware(fm *fingerprint.Manager, tm *token.Manager) *Middleware {
	return &Middleware{
		fingerprintManager: fm,
		tokenManager:       tm,
	}
}
