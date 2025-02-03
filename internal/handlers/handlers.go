package handlers

import (
	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/db"
)

type Handler struct {
	fingerprintManager *fingerprint.Manager
	tokenManager       *token.Manager
	conn               *db.Connection
}

func NewHandler(fm *fingerprint.Manager, tm *token.Manager, conn *db.Connection) *Handler {
	return &Handler{
		fingerprintManager: fm,
		tokenManager:       tm,
		conn:               conn,
	}
}
