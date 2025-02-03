package models_test

import (
	"encoding/base64"
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/stretchr/testify/assert"
	"testing"
)

// TestWebFingerprintHash tests the hash generation for web fingerprints
func TestWebFingerprintHash(t *testing.T) {
	wf := &models.WebFingerprint{
		BaseFingerprint: models.BaseFingerprint{
			ClientType: models.WebClient,
			IP:         "192.168.1.1",
			UserAgent:  "Mozilla/5.0",
			RandomSalt: "salt123",
		},
		ScreenResolution: "1920x1080",
		ColorDepth:       "24",
		TimeZone:         "UTC+1",
		Language:         "en-US",
	}

	hash := wf.Hash()
	assert.NotEmpty(t, hash)

	_, err := base64.URLEncoding.DecodeString(hash)
	assert.NoError(t, err)

	assert.Equal(t, hash, wf.Hash())
}

func TestMobileFingerprintHash(t *testing.T) {
	mf := &models.MobileFingerprint{
		BaseFingerprint: models.BaseFingerprint{
			ClientType: models.MobileClient,
			IP:         "192.168.1.1",
			UserAgent:  "Android/5.0",
			RandomSalt: "salt123",
		},
		DeviceModel:   "Pixel 6",
		OSVersion:     "Android 12",
		ScreenDensity: "420dpi",
		IsEmulator:    false,
	}

	hash := mf.Hash()

	assert.NotEmpty(t, hash)
	_, err := base64.URLEncoding.DecodeString(hash)
	assert.NoError(t, err)
	assert.Equal(t, hash, mf.Hash())
}
