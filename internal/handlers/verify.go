package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/joeariasc/go-auth/internal/models"
	"github.com/joeariasc/go-auth/internal/utils"
)

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	claims := r.Context().Value(utils.ClaimsKey).(*models.UserClaims)

	// Return user info
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username":   claims.Username,
		"clientType": claims.ClientType,
		"valid":      true,
	})
}
