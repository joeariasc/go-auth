package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"github.com/joeariasc/go-auth/internal/models"
	"net"
	"net/http"
	"strings"
)

func GetClientType(h http.Header) (models.ClientType, error) {
	// Parse client type first
	clientType := models.ClientType(h.Get("X-Client-Type"))

	if !clientType.IsValid() {
		return "", errors.New("invalid client type")
	}

	return clientType, nil

}

// SetFingerprintCookie sets the secure fingerprint cookie
func SetFingerprintCookie(w http.ResponseWriter, fingerprint string) {
	// Hash the fingerprint before storing in cookie
	hashedFingerprint := sha256.Sum256([]byte(fingerprint))
	encodedFingerprint := base64.URLEncoding.EncodeToString(hashedFingerprint[:])

	http.SetCookie(w, &http.Cookie{
		Name:     "fingerprint",
		Value:    encodedFingerprint,
		Path:     "/",
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   3600, // 1 hour
	})
}

// GetIP returns the ip address from the http request
func GetIP(r *http.Request) (string, error) {
	ips := r.Header.Get("X-Forwarded-For")
	splitIps := strings.Split(ips, ",")

	if len(splitIps) > 0 {
		// get last IP in list since ELB prepends other user defined IPs,
		// meaning the last one is the actual client IP.
		netIP := net.ParseIP(splitIps[len(splitIps)-1])
		if netIP != nil {
			return netIP.String(), nil
		}
	}

	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", err
	}

	netIP := net.ParseIP(ip)
	if netIP != nil {
		ip := netIP.String()
		if ip == "::1" {
			return "127.0.0.1", nil
		}
		return ip, nil
	}

	return "", errors.New("IP not found")
}
