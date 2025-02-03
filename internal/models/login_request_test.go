package models_test

import (
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestValidateLoginRequest(t *testing.T) {
	testCases := []struct {
		name        string
		request     models.LoginRequest
		expectError bool
	}{
		{
			name: "Valid Web Client Request",
			request: models.LoginRequest{
				Username: "webuser",
				Password: "password123",
				ClientData: map[string]string{
					"clientType":       "web",
					"screenResolution": "1920x1080",
					"colorDepth":       "24",
					"timeZone":         "UTC",
					"language":         "en-US",
				},
			},
			expectError: false,
		},
		{
			name: "Valid Mobile Client Request",
			request: models.LoginRequest{
				Username: "mobileuser",
				Password: "password456",
				ClientData: map[string]string{
					"clientType":    "mobile",
					"deviceModel":   "iPhone 12",
					"osVersion":     "14.5",
					"carrierInfo":   "Verizon",
					"screenDensity": "3x",
					"buildNumber":   "18E199",
					"isEmulator":    "false",
				},
			},
			expectError: false,
		},
		{
			name: "Missing Web Client Field",
			request: models.LoginRequest{
				Username: "webuser",
				Password: "password123",
				ClientData: map[string]string{
					"clientType":       "web",
					"screenResolution": "1920x1080",
					"colorDepth":       "24",
					"timeZone":         "UTC",
					// Missing language
				},
			},
			expectError: true,
		},
		{
			name: "Missing Mobile Client Field",
			request: models.LoginRequest{
				Username: "mobileuser",
				Password: "password456",
				ClientData: map[string]string{
					"clientType":    "mobile",
					"deviceModel":   "iPhone 12",
					"osVersion":     "14.5",
					"carrierInfo":   "Verizon",
					"screenDensity": "3x",
					// Missing buildNumber
				},
			},
			expectError: true,
		},
		{
			name: "Invalid Client Type",
			request: models.LoginRequest{
				Username: "invaliduser",
				Password: "password789",
				ClientData: map[string]string{
					"clientType": "invalid",
				},
			},
			expectError: true,
		},
		{
			name: "Empty ClientData",
			request: models.LoginRequest{
				Username:   "emptyuser",
				Password:   "password000",
				ClientData: map[string]string{},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := models.ValidateLoginRequest(tc.request)

			if tc.expectError {
				assert.Error(t, err, "Test case should fail: %s", tc.name)
			} else {
				assert.NoError(t, err, "Test case should pass: %s", tc.name)
			}
		})
	}
}

func TestValidateLoginRequest_MissingRequiredFields(t *testing.T) {
	testCases := []struct {
		name        string
		request     models.LoginRequest
		expectError bool
	}{
		{
			name: "Missing Username",
			request: models.LoginRequest{
				Password: "password123",
				ClientData: map[string]string{
					"clientType":       "web",
					"screenResolution": "1920x1080",
					"colorDepth":       "24",
					"timeZone":         "UTC",
					"language":         "en-US",
				},
			},
			expectError: true,
		},
		{
			name: "Missing Password",
			request: models.LoginRequest{
				Username: "webuser",
				ClientData: map[string]string{
					"clientType":       "web",
					"screenResolution": "1920x1080",
					"colorDepth":       "24",
					"timeZone":         "UTC",
					"language":         "en-US",
				},
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := models.ValidateLoginRequest(tc.request)

			if tc.expectError {
				assert.Error(t, err, "Test case should fail: %s", tc.name)
			} else {
				assert.NoError(t, err, "Test case should pass: %s", tc.name)
			}
		})
	}
}
