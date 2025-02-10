package fingerprint

import (
	"fmt"
	"log"

	"github.com/joeariasc/go-auth/internal/models"
	"github.com/joeariasc/go-auth/internal/utils"
)

type Params struct {
	ClientType        models.ClientType
	ClientFingerprint string
	Ip                string
	UserAgent         string
}

type Manager struct {
	baseFingerprint map[string]*models.BaseFingerprint
}

func NewManager() *Manager {
	return &Manager{
		baseFingerprint: make(map[string]*models.BaseFingerprint),
	}
}

func (m *Manager) GenerateFingerprint(params Params) (string, error) {
	base := models.BaseFingerprint{
		ClientType: params.ClientType,
		IP:         params.Ip,
		UserAgent:  params.UserAgent,
	}

	fmt.Print("base fingerprint: ")
	utils.PrettyPrintData(base)

	fingerprintHash := base.Hash()

	log.Printf("Generated fingerprint hash: %s\n", fingerprintHash)

	return fingerprintHash, nil
}
