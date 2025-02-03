package test_utils

import (
	"github.com/joeariasc/go-auth/internal/db/entity"
	"github.com/stretchr/testify/mock"
	"time"
)

// MockConnection provides a mock implementation of the Connection struct
type MockConnection struct {
	mock.Mock
}

func (m *MockConnection) Insert(user *entity.User) (int, error) {
	args := m.Called(user)
	return args.Int(0), args.Error(1)
}

func (m *MockConnection) SetFingerprint(username string, fingerprint string) error {
	args := m.Called(username, fingerprint)
	return args.Error(0)
}

func (m *MockConnection) GetUser(username string) (*entity.User, error) {
	args := m.Called(username)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockConnection) Retrieve(id int) (*entity.User, error) {
	args := m.Called(id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.User), args.Error(1)
}

func (m *MockConnection) List(offset int) ([]*entity.User, error) {
	args := m.Called(offset)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]*entity.User), args.Error(1)
}

// CreateMockUser Helper method to create a mock user for testing
func CreateMockUser(username string) *entity.User {
	return &entity.User{
		Id:          1,
		Username:    username,
		CreatedAt:   time.Now(),
		Description: "Test User",
		Fingerprint: "",
		Secret:      "mocksecret",
	}
}
