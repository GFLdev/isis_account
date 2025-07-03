package types

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Account represents the account table row.
type Account struct {
	// AccountID is the account's ID.
	AccountID uuid.UUID `json:"account_id" validate:"required"`
	// RoleID is the account's role ID.
	RoleID uuid.UUID `json:"role_id" validate:"required"`
	// Username is the account's username.
	Username string `json:"username" validate:"required"`
	// Name is the account's user first name.
	Name string `json:"name" validate:"required"`
	// Surname is the account's user surname.
	Surname string `json:"surname" validate:"required"`
	// Email is the account's user email.
	Email string `json:"email" validate:"required"`
	// Password is the account's bcrypt hash.
	Password []byte `json:"password" validate:"required"`
	// IsActive is the account's active status.
	IsActive bool `json:"is_active" validate:"required"`
	// LoginCount is the account's login count.
	LoginCount int `json:"login_count" validate:"min=0"`
	// LastLoginAt is the account's last login date.
	LastLoginAt sql.NullTime `json:"last_login_at" validate:""`
	// CreatedAt is the account's creation date.
	CreatedAt time.Time `json:"created_at" validate:"required"`
	// ModifiedAt is the account's last modification date.
	ModifiedAt sql.NullTime `json:"modified_at" validate:""`
}
