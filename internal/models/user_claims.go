package models

import "github.com/golang-jwt/jwt/v5"

type UserClaims struct {
	jwt.RegisteredClaims
	Username    string `json:"username"`
	Fingerprint string `json:"fingerprint"`
	ClientType  string `json:"client_type"`
}
