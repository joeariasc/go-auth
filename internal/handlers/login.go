package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/models"
	"log"
	"net/http"
)

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.LoginRequest

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if err := models.ValidateLoginRequest(req); err != nil {
		http.Error(w, "Invalid client data request", http.StatusBadRequest)
		return
	}

	if req.Username == "wawandco" && req.Password == "wwco2025" {
		clientType := models.ClientType(req.ClientData["clientType"])

		newFingerprint, err := h.fingerprintManager.GenerateFingerprint(r, req.ClientData)

		if err != nil {
			http.Error(w, "Failed to generate fingerprint", http.StatusInternalServerError)
			return
		}

		fmt.Println("newFingerprint", newFingerprint)

		err = h.conn.SetFingerprint(req.Username, newFingerprint)

		if err != nil {
			log.Printf("Failed to set new fingerprint: %v", err)
			http.Error(w, "Failed to set fingerprint", http.StatusInternalServerError)
		}

		tokenParams := token.Params{
			Username:    req.Username,
			Fingerprint: newFingerprint,
			ClientType:  clientType,
			Secret:      "",
		}

		// Generate token
		newToken, err := h.tokenManager.GenerateToken(tokenParams)

		if err != nil {
			http.Error(w, "Failed to generate token", http.StatusInternalServerError)
			return
		}

		// For web clients, set the fingerprint cookie
		if clientType == models.WebClient {
			http.SetCookie(w, &http.Cookie{
				Name:     "fingerprint",
				Value:    newFingerprint,
				Path:     "/",
				HttpOnly: true,
				Secure:   true,
				SameSite: http.SameSiteNoneMode,
				MaxAge:   3600,
			})
		}

		// Send response
		response := models.LoginResponse{
			Token:     newToken,
			ExpiresIn: 300, // 5 mins
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
