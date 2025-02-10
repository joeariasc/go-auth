package handlers

import (
	"encoding/json"
	"errors"
	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/joeariasc/go-auth/internal/utils"
	"log"
	"net/http"
)

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	//get cookie
	cookie, err := r.Cookie("token")
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			log.Println("No token cookie")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		log.Println("Error getting token cookie")
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
		log.Printf("Failed to get IP: %v", err)
		http.Error(w, "Failed to get IP", http.StatusInternalServerError)
		return
	}

	//get token from cookie
	tokenString := cookie.Value

	log.Printf("tokenString: %s\n", tokenString)

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

	newFingerprint, err := h.fingerprintManager.GenerateFingerprint(fingerprintParams)

	// Verify token
	claims, err := h.tokenManager.VerifyToken(tokenString, newFingerprint)
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
