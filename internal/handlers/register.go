package handlers

import (
	"crypto/md5"
	"encoding/json"
	"fmt"
	"github.com/joeariasc/go-auth/internal/db/entity"
	"github.com/joeariasc/go-auth/internal/models"
	"log"
	"net/http"
	"time"
)

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	errValidate := req.Validate()
	if errValidate != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	_, err := h.conn.GetUser(req.Username)
	if err == nil {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	user := entity.User{
		Username:    req.Username,
		CreatedAt:   time.Now(),
		Description: req.Description,
		Fingerprint: "",
		Secret:      fmt.Sprintf("%x", md5.Sum([]byte(req.Username))),
	}

	id, err := h.conn.Insert(&user)
	if err != nil {
		log.Printf("Error while inserting user: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}

	response := models.RegisterResponse{
		Username: req.Username,
		ID:       id,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)

}
