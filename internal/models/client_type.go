package models

type ClientType string

const (
	WebClient    ClientType = "web"
	MobileClient ClientType = "mobile"
)

func (ct ClientType) IsValid() bool {
	switch ct {
	case WebClient, MobileClient:
		return true
	default:
		return false
	}
}
