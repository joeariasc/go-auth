package entity

import "time"

type User struct {
	Id          int64
	Username    string
	CreatedAt   time.Time
	Description string
	Fingerprint string
	Secret      string
}
