package models_test

import (
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestClientTypeValidation(t *testing.T) {
	testCases := []struct {
		name       string
		clientType models.ClientType
		expected   bool
	}{
		{"Web Client", models.WebClient, true},
		{"Mobile Client", models.MobileClient, true},
		{"Invalid Client Type", models.ClientType("desktop"), false},
		{"Empty Client Type", models.ClientType(""), false},
		{"Case Sensitive Check", models.ClientType("WEB"), false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.clientType.IsValid(),
				"Validation failed for client type: %s", tc.clientType)
		})
	}
}
