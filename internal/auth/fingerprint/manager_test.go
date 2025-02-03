package fingerprint

import (
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestManager(t *testing.T) {
	tests := []struct {
		name       string
		clientType models.ClientType
		clientData map[string]string
		wantErr    bool
	}{
		{
			name:       "Web Client",
			clientType: models.WebClient,
			clientData: map[string]string{
				"clientType":       string(models.WebClient),
				"screenResolution": "1920x1080",
				"colorDepth":       "24",
				"timeZone":         "UTC+1",
				"language":         "en-US",
			},
			wantErr: false,
		},
		{
			name:       "Android Client",
			clientType: models.MobileClient,
			clientData: map[string]string{
				"clientType":    string(models.MobileClient),
				"deviceModel":   "Pixel 6",
				"osVersion":     "Android 12",
				"screenDensity": "420dpi",
				"isEmulator":    "false",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager := NewManager()
			req, _ := http.NewRequest(http.MethodGet, "http://example.com", nil)
			req.Header.Set("User-Agent", "TestAgent")
			req.Header.Set("X-Forwarded-For", "192.168.1.1")

			hash, err := manager.GenerateFingerprint(req, tt.clientData)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, hash)

			// Verify the fingerprint was stored in the correct map
			if tt.clientType == models.WebClient {
				fingerprint, exists := manager.webFingerprints[hash]
				assert.True(t, exists)
				assert.Equal(t, tt.clientData["screenResolution"], fingerprint.ScreenResolution)
			} else {
				fingerprint, exists := manager.mobileFingerprints[hash]
				assert.True(t, exists)
				assert.Equal(t, tt.clientData["deviceModel"], fingerprint.DeviceModel)
			}
		})
	}
}

// TestManagerEdgeCases tests edge cases and error conditions
func TestManagerEdgeCases(t *testing.T) {
	manager := NewManager()
	req, _ := http.NewRequest("GET", "http://example.com", nil)

	tests := []struct {
		name       string
		clientData map[string]string
		wantErr    bool
	}{
		{
			name: "Missing Client Type",
			clientData: map[string]string{
				"deviceId": "test123",
			},
			wantErr: true,
		},
		{
			name: "Invalid Client Type",
			clientData: map[string]string{
				"clientType": "invalid",
				"deviceId":   "test123",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := manager.GenerateFingerprint(req, tt.clientData)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
