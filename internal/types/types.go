package types

import (
	"net"
	"time"

	"github.com/google/uuid"
)

// AccountActivityFilter represents the account activity filter enum.
type AccountActivityFilter string

const (
	// ActiveAccountFilter represents active accounts filter value.
	ActiveAccountFilter AccountActivityFilter = "A"
	// InactiveAccountFilter represents inactive accounts filter value.
	InactiveAccountFilter AccountActivityFilter = "I"
	// NoActivityAccountFilter represents no account activity filter value.
	NoActivityAccountFilter AccountActivityFilter = "N"
)

// ModuleName represents the modules' name enum in database.
type ModuleName string

const (
	// AccountModule is the ISIS Account module name.
	AccountModule ModuleName = "account"
	// FinanceModule is the ISIS Finance module name.
	FinanceModule ModuleName = "finance"
	// DriveModule is the ISIS Drive module name.
	DriveModule ModuleName = "drive"
	// CalendarModule is the ISIS Calendar module name.
	CalendarModule ModuleName = "calendar"
	// AIModule is the ISIS AI module name.
	AIModule ModuleName = "ai"
)

// GetAccountsFilters represents the filters for get all accounts query.
type GetAccountsFilters struct {
	// Limit is the result slice length limit.
	Limit int `validate:"min=0"`
	// Offset is the result offset. Offset < Limit (custom validation).
	Offset int `validate:"min=0"`
	// RoleID filter by user's role filter.
	RoleID uuid.UUID `validate:"uuid"`
	// IsActive filter by user activity.
	IsActive AccountActivityFilter `validate:"oneof=A I N"`
}

// LoginAttemptConfig represents the parameters of a login attempt.
type LoginAttemptConfig struct {
	// AccountID is the account of the login attempt.
	AccountID uuid.UUID `json:"account_id" validate:"required,uuid"`
	// AttemptedAt is the timestamp of the attempt.
	AttemptedAt time.Time `json:"attempted_at" validate:"required"`
	// Success is the attempt success status.
	Success bool `json:"success" validate:"boolean"`
	// IPAddress is the client's IP address that attempted the login.
	IPAddress net.IP `json:"ip_address" validate:"required,ip_with_localhost"`
	// UserAgent is the client's user agent that attempted the login.
	UserAgent string `json:"user_agent" validate:"required"`
}

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
	LastLoginAt time.Time `json:"last_login_at"`
	// CreatedAt is the account's creation date.
	CreatedAt time.Time `json:"created_at" validate:"required"`
	// ModifiedAt is the account's last modification date.
	ModifiedAt time.Time `json:"modified_at"`
}

// RefreshToken represents the refresh_token table row.
type RefreshToken struct {
	// RefreshTokenID is the refresh token's ID, used as the refresh token itself.
	RefreshTokenID string `json:"refresh_token_id" validate:"required"`
	// AccountID is the account that has the current refresh token.
	AccountID uuid.UUID `json:"account_id" validate:"required,uuid"`
	// ExpirationDate is the refresh token's expiration date.
	ExpirationDate time.Time `json:"expiration_date" validate:"required"`
}

// LoginAttempt represents the login_attempt table row.
type LoginAttempt struct {
	// LoginAttemptID is the login attempt's ID.
	LoginAttemptID uuid.UUID `json:"login_attempt_id" validate:"required,uuid"`
	// AccountID is the account of the login attempt.
	AccountID uuid.UUID `json:"account_id" validate:"required,uuid"`
	// AttemptedAt is the timestamp of the attempt.
	AttemptedAt time.Time `json:"attempted_at" validate:"required"`
	// Success is the attempt success status.
	Success bool `json:"success" validate:"required,boolean"`
	// IPAddress is the client's IP address that attempted the login.
	IPAddress net.IP `json:"ip_address" validate:"required,ip_with_localhost"`
	// UserAgent is the client's user agent that attempted the login.
	UserAgent string `json:"user_agent" validate:"required"`
}

// Module represents the module table row.
type Module struct {
	// ModuleName is the module's name.
	ModuleName ModuleName
	// Description is the module's description.
	Description string
}

// Role represents the role table row.
type Role struct {
	// RoleID is the role's ID.
	RoleID uuid.UUID `json:"role_id" validate:"required,uuid"`
	// Name is the role's name.
	Name string `json:"name" validate:"required,max=50"`
	// Description is the role's description.
	Description string `json:"description" validate:"required,max=1000"`
	// CreatedAt is the role's creation timestamp.
	CreatedAt time.Time `json:"created_at"`
	// ModifiedAt is the role's last modification timestamp.
	ModifiedAt time.Time `json:"modified_at"`
}

// RoleModule represents the role_module table row.
type RoleModule struct {
	// RoleID is the role's ID of the permission.
	RoleID uuid.UUID
	// ModuleName is the module's name of the permission.
	ModuleName ModuleName
	// Elevated is a flag to check if the user has elevated permissions (admin).
	Elevated bool
}
