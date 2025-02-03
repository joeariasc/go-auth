package models

import "github.com/go-playground/validator/v10"

type RegisterRequest struct {
	Username    string `json:"username" validate:"required"`
	Description string `json:"description" validate:"required"`
}

func (req RegisterRequest) Validate() error {
	return validator.New().Struct(req)
}

type RegisterResponse struct {
	Username string `json:"username"`
	ID       int    `json:"id"`
}
