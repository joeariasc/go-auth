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
	RandomSalt string
}

type WebFingerprint struct {
	BaseFingerprint
	ScreenResolution string
	ColorDepth       string
	TimeZone         string
	Language         string
}

type MobileFingerprint struct {
	BaseFingerprint
	DeviceModel   string
	OSVersion     string
	ScreenDensity string
	IsEmulator    bool
}

// Hash methods for different fingerprint types
func (wf *WebFingerprint) Hash() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%s",
		wf.ClientType,
		wf.IP,
		wf.UserAgent,
		wf.RandomSalt,
		wf.ScreenResolution,
		wf.ColorDepth,
		wf.TimeZone,
		wf.Language,
	)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}

func (mf *MobileFingerprint) Hash() string {
	data := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%v",
		mf.ClientType,
		mf.IP,
		mf.UserAgent,
		mf.RandomSalt,
		mf.DeviceModel,
		mf.OSVersion,
		mf.ScreenDensity,
		mf.IsEmulator,
	)
	hash := sha256.Sum256([]byte(data))
	return base64.URLEncoding.EncodeToString(hash[:])
}
