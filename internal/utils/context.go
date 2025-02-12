package utils

import (
	"errors"
)

var ErrClaimsNotFound = errors.New("claims not found in context")

// Context key type to avoid collisions
type contextKey string

const ClaimsKey contextKey = "claims"
