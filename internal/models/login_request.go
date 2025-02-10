package models

import (
	"github.com/go-playground/validator/v10"
)

type LoginRequest struct {
	Username string `json:"username" validate:"required"`
	Password string `json:"password" validate:"required"`
}

type LoginResponse struct {
	Success         bool   `json:"success"`
	Message         string `json:"message"`
	SessionDuration int    `json:"sessionDuration"`
}

// ValidateLoginRequest validates a login request
func ValidateLoginRequest(req LoginRequest) error {
	return validator.New().Struct(req)
}
