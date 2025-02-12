package middleware

import (
	"context"
	"errors"
	"net/http"

	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/joeariasc/go-auth/internal/utils"
)

func (m *Middleware) AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract token from cookie
		cookie, err := r.Cookie("session")
		if err != nil {
			if errors.Is(err, http.ErrNoCookie) {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		clientType := models.ClientType(r.Header.Get("X-Client-Type"))
		if !clientType.IsValid() {
			http.Error(w, "Invalid client type", http.StatusBadRequest)
			return
		}

		ip, err := utils.GetIP(r)
		if err != nil {
			http.Error(w, "Failed to get IP", http.StatusInternalServerError)
			return
		}

		//get token from cookie
		tokenString := cookie.Value

		clientFingerprint := utils.SanitizeHeader(r.Header.Get("X-Fingerprint"))
		if clientFingerprint == "" {
			http.Error(w, "Missing Fingerprint", http.StatusUnauthorized)
			return
		}

		fingerprintParams := fingerprint.Params{
			ClientType:        clientType,
			ClientFingerprint: clientFingerprint,
			Ip:                ip,
			UserAgent:         utils.SanitizeHeader(r.UserAgent()),
		}

		newFingerprint, err := m.fingerprintManager.GenerateFingerprint(fingerprintParams)

		if err != nil {
			http.Error(w, "Failed to generate fingerprint", http.StatusInternalServerError)
			return
		}

		// Verify token
		claims, err := m.tokenManager.VerifyToken(tokenString, newFingerprint)
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

		// Add validated claims to request context
		ctx := context.WithValue(r.Context(), utils.ClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}
