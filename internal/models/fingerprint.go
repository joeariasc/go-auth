package models

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

type BaseFingerprint struct {
	ClientType ClientType
	IP         string
	UserAgent  string
}

type MobileFingerprint struct {
	BaseFingerprint
	DeviceModel   string
	OSVersion     string
	ScreenDensity string
	IsEmulator    bool
}

func (bf BaseFingerprint) Hash() string {
	data := fmt.Sprintf("%s|%s|%s",
		bf.ClientType,
		bf.IP,
		bf.UserAgent,
	)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}
