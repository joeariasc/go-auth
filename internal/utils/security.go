package utils

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
)

func SanitizeHeader(header string) string {
	// Remove any control characters and trim spaces
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, strings.TrimSpace(header))
}

func GenerateRandomSalt() string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return ""
	}
	return hex.EncodeToString(salt)
}
