package types

import (
	"time"

	"github.com/google/uuid"
)

// Account represents the account table row.
type Account struct {
	// AccountID is the account's ID.
	AccountID uuid.UUID
	// RoleID is the account's role ID.
	RoleID uuid.UUID
	// Username is the account's username.
	Username string
	// Name is the account's user first name.
	Name string
	// Surname is the account's user surname.
	Surname string
	// Email is the account's user email.
	Email string
	// Password is the account's bcrypt hash.
	Password []byte
	// IsActive is the account's active status.
	IsActive bool
	// LoginCount is the account's login count.
	LoginCount int
	// LastLoginAt is the account's last login date.
	LastLoginAt time.Time
	// CreatedAt is the account's creation date.
	CreatedAt time.Time
	// ModifiedAt is the account's last modification date.
	ModifiedAt time.Time
}
