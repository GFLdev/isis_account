package types

import (
	"database/sql"
	"time"

	"github.com/google/uuid"
)

// Account represents the account table row.
type Account struct {
	// AccountID is the account's ID.
	AccountID uuid.UUID `json:"account_id" validate:"required,uuid"`
	// RoleID is the account's role ID.
	RoleID uuid.UUID `json:"role_id" validate:"required,uuid"`
	// Username is the account's username.
	Username string `json:"username" validate:"required,min=4,max=30"`
	// Name is the account's user first name.
	Name string `json:"name" validate:"required,max=100"`
	// Surname is the account's user surname.
	Surname string `json:"surname" validate:"required,max=100"`
	// Email is the account's user email.
	Email string `json:"email" validate:"required,email,max=100"`
	// Password is the account's bcrypt hash.
	Password []byte `json:"password" validate:"required,max=72"`
	// IsActive is the account's active status.
	IsActive bool `json:"is_active" validate:"required,boolean"`
	// LoginCount is the account's login count.
	LoginCount int `json:"login_count" validate:"number,min=0"`
	// LastLoginAt is the account's last login date.
	LastLoginAt sql.NullTime `json:"last_login_at"`
	// CreatedAt is the account's creation date.
	CreatedAt time.Time `json:"created_at" validate:"required"`
	// ModifiedAt is the account's last modification date.
	ModifiedAt sql.NullTime `json:"modified_at"`
}

type RefreshToken struct {
	RefreshTokenID uuid.UUID `json:"refresh_token_id" validate:"required,uuid"`
	AccountID      uuid.UUID `json:"account_id" validate:"required,uuid"`
	ExpirationDate time.Time `json:"expiration_date" validate:"required"`
}
