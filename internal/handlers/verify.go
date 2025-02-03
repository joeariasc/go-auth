package handlers

import (
	"encoding/json"
	"errors"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"net/http"
	"strings"
)

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	clientToken := r.Header.Get("Authorization")
	if clientToken == "" {
		http.Error(w, "Missing token", http.StatusUnauthorized)
		return
	}

	// Remove 'Bearer ' prefix if present
	clientToken = strings.TrimPrefix(clientToken, "Bearer ")

	// Get fingerprint based on client type
	var newFingerprint string
	if cookie, err := r.Cookie("fingerprint"); err == nil {
		// Web client
		newFingerprint = cookie.Value
	} else {
		// Mobile client - get from header
		newFingerprint = r.Header.Get("X-Fingerprint")
	}

	if newFingerprint == "" {
		http.Error(w, "Missing fingerprint", http.StatusUnauthorized)
		return
	}

	// Verify token
	claims, err := h.tokenManager.VerifyToken(clientToken, newFingerprint)
	if err != nil {
		switch {
		case errors.Is(err, token.ErrTokenExpired):
			http.Error(w, "Token expired", http.StatusUnauthorized)
		case errors.Is(err, token.ErrInvalidFingerprint):
			http.Error(w, "Invalid fingerprint", http.StatusUnauthorized)
		default:
			http.Error(w, "Invalid token", http.StatusUnauthorized)
		}
		return
	}

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":   claims.Username,
		"clientType": claims.ClientType,
		"valid":      true,
	})
}
