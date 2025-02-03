package models

import (
	"github.com/go-playground/validator/v10"
	"strings"
)

type LoginRequest struct {
	Username   string            `json:"username" validate:"required"`
	Password   string            `json:"password" validate:"required"`
	ClientData map[string]string `json:"clientData" validate:"required,clientDataValidation"`
}

type LoginResponse struct {
	Token     string `json:"token"`
	ExpiresIn int    `json:"expiresIn"`
}

// ValidateLoginRequest validates a login request
func ValidateLoginRequest(req LoginRequest) error {
	validate := customValidator()
	return validate.Struct(req)
}

// customValidator creates a custom validator with our special validation
func customValidator() *validator.Validate {
	validate := validator.New()

	// Register a custom validation function for ClientData
	validate.RegisterValidation("clientDataValidation", validateClientData)

	return validate
}

// validateClientData is a custom validation function for client data
func validateClientData(fl validator.FieldLevel) bool {
	// Get the client data map
	clientData, ok := fl.Field().Interface().(map[string]string)
	if !ok {
		return false
	}

	// Check if clientType exists
	clientType, exists := clientData["clientType"]
	if !exists {
		return false
	}

	// Validate based on client type
	switch strings.ToLower(clientType) {
	case "web":
		return validateWebClientData(clientData)
	case "mobile":
		return validateMobileClientData(clientData)
	default:
		return false
	}
}

// validateWebClientData checks required fields for web clients
func validateWebClientData(clientData map[string]string) bool {
	requiredWebFields := []string{
		"screenResolution",
		"colorDepth",
		"timeZone",
		"language",
	}

	for _, field := range requiredWebFields {
		if _, exists := clientData[field]; !exists {
			return false
		}
	}
	return true
}

// validateMobileClientData checks required fields for mobile clients
func validateMobileClientData(clientData map[string]string) bool {
	requiredMobileFields := []string{
		"deviceModel",
		"osVersion",
		"screenDensity",
		"isEmulator",
	}

	for _, field := range requiredMobileFields {
		if _, exists := clientData[field]; !exists {
			return false
		}
	}
	return true
}
