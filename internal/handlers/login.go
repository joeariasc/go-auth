package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"log"
	"net/http"

	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/joeariasc/go-auth/internal/utils"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	clientType := models.ClientType(r.Header.Get("X-Client-Type"))
	if !clientType.IsValid() {
		http.Error(w, "Invalid client type", http.StatusBadRequest)
		return
	}

	var req models.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := h.conn.GetUser(req.Username)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	if req.Password == "wwco2025" {
		clientFingerprint := utils.SanitizeHeader(r.Header.Get("X-Fingerprint"))

		log.Printf("Client Fingerprint: %s", clientFingerprint)

		ip, err := utils.GetIP(r)

		if err != nil {
			log.Printf("Failed to get IP: %v", err)
			http.Error(w, "Failed to get IP", http.StatusInternalServerError)
			return
		}

		log.Printf("Ip from the request: %s\n", ip)

		fingerprintParams := fingerprint.Params{
			ClientType:        clientType,
			ClientFingerprint: clientFingerprint,
			Ip:                ip,
			UserAgent:         utils.SanitizeHeader(r.UserAgent()),
		}

		newFingerprint, err := h.fingerprintManager.GenerateFingerprint(fingerprintParams)

		if err != nil {
			fmt.Println("Failed to generate fingerprint: ", err)
			http.Error(w, "Failed to generate fingerprint", http.StatusInternalServerError)
			return
		}

		fmt.Println("newFingerprint", newFingerprint)

		_, err = h.conn.SetFingerprint(req.Username, newFingerprint)

		if err != nil {
			log.Printf("Failed to set new fingerprint: %v", err)
			http.Error(w, "Failed to set fingerprint", http.StatusInternalServerError)
			return
		}

		tokenParams := token.Params{
			Username:    req.Username,
			Fingerprint: newFingerprint,
			ClientType:  clientType,
			Secret:      h.tokenManager.SecretKey,
		}

		// Generate token
		newToken, err := h.tokenManager.GenerateToken(tokenParams)

		if err != nil {
			log.Println("Failed to generate token: ", err)
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// For web clients, set the fingerprint cookie
		if clientType == models.WebClient {
			http.SetCookie(w, &http.Cookie{
				Name:     "token",
				Value:    newToken,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteNoneMode,
				MaxAge:   int(h.tokenManager.TokenDuration),
			})
		}

		// Send response
		response := models.LoginResponse{
			Success:         true,
			Message:         "Login successful",
			SessionDuration: int(h.tokenManager.TokenDuration),
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(response)
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		response := ErrorResponse{
			Message: "Invalid username or password",
			Status:  http.StatusUnauthorized,
		}
		json.NewEncoder(w).Encode(response)
	}

}
