package test_utils

import (
	"github.com/joeariasc/go-auth/internal/auth/fingerprint"
	"github.com/joeariasc/go-auth/internal/auth/token"
	"github.com/joeariasc/go-auth/internal/db"
	"github.com/stretchr/testify/mock"
)

// MockHandler provides a mock implementation of the Handler struct
type MockHandler struct {
	mock.Mock
}

// NewMockHandler creates a new MockHandler
func NewMockHandler() *MockHandler {
	return &MockHandler{}
}

// Implement methods that mirror the original Handler's methods
// Add specific mock behaviors as needed for your tests

// OnGetFingerprintManager sets up a mock for fingerprintManager
func (m *MockHandler) OnGetFingerprintManager() *fingerprint.Manager {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*fingerprint.Manager)
}

// OnGetTokenManager sets up a mock for tokenManager
func (m *MockHandler) OnGetTokenManager() *token.Manager {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*token.Manager)
}

// OnGetConnection sets up a mock for db connection
func (m *MockHandler) OnGetConnection() *db.Connection {
	args := m.Called()
	if args.Get(0) == nil {
		return nil
	}
	return args.Get(0).(*db.Connection)
}
