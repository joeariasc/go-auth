package fingerprint

import (
	"errors"
	"github.com/joeariasc/go-auth/internal/models"
	"github.com/joeariasc/go-auth/internal/utils"
	"log"
	"net/http"
)

type Manager struct {
	webFingerprints    map[string]*models.WebFingerprint
	mobileFingerprints map[string]*models.MobileFingerprint
}

func NewManager() *Manager {
	return &Manager{
		webFingerprints:    make(map[string]*models.WebFingerprint),
		mobileFingerprints: make(map[string]*models.MobileFingerprint),
	}
}

func (m *Manager) GenerateFingerprint(r *http.Request, clientData map[string]string) (string, error) {
	clientType := models.ClientType(clientData["clientType"])

	if !clientType.IsValid() {
		return "", errors.New("invalid client type")
	}

	log.Printf("Generating fingerprint for clientType %s\n", clientType)

	clientIp, err := utils.GetIP(r)
	if err != nil {
		return "", err
	}

	base := models.BaseFingerprint{
		ClientType: clientType,
		IP:         clientIp,
		UserAgent:  utils.SanitizeHeader(r.UserAgent()),
		RandomSalt: utils.GenerateRandomSalt(),
	}

	utils.PrettyPrintData(base)

	var fingerprintHash string

	switch clientType {
	case models.WebClient:
		webFingerprint := &models.WebFingerprint{
			BaseFingerprint:  base,
			ScreenResolution: clientData["screenResolution"],
			ColorDepth:       clientData["colorDepth"],
			TimeZone:         clientData["timeZone"],
			Language:         clientData["language"],
		}
		fingerprintHash = webFingerprint.Hash()
		m.webFingerprints[fingerprintHash] = webFingerprint

	case models.MobileClient:
		mobileFingerprint := &models.MobileFingerprint{
			BaseFingerprint: base,
			DeviceModel:     clientData["deviceModel"],
			OSVersion:       clientData["osVersion"],
			ScreenDensity:   clientData["screenDensity"],
			IsEmulator:      clientData["isEmulator"] == "true",
		}

		fingerprintHash = mobileFingerprint.Hash()
		m.mobileFingerprints[fingerprintHash] = mobileFingerprint
	}

	log.Printf("Generated fingerprint hash: %s\n", fingerprintHash)

	return fingerprintHash, nil
}
