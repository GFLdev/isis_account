package types

import (
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Set represents a set data structrure.
type Set[T comparable] struct {
	// val is the set value.
	val map[T]bool
	// mux is the mutex for accessing and modifying the set.
	mux sync.Mutex
}

// Add adds a new value to set.
func (set *Set[T]) Add(val T) {
	set.mux.Lock()
	defer set.mux.Unlock()
	set.val[val] = true
}

// Remove removes a value from set, if it exists.
func (set *Set[T]) Remove(val T) {
	set.mux.Lock()
	defer set.mux.Unlock()
	delete(set.val, val)
}

// Clear remove all values from set.
func (set *Set[T]) Clear() {
	set.mux.Lock()
	defer set.mux.Unlock()
	set.val = make(map[T]bool)
}

// Contains checks if value is in set.
func (set *Set[T]) Contains(val T) bool {
	set.mux.Lock()
	defer set.mux.Unlock()
	_, ok := set.val[val]
	if ok {
		return true
	}
	return false
}

// ToSlice returns a slice representation of the set.
func (set *Set[T]) ToSlice() []T {
	set.mux.Lock()
	defer set.mux.Unlock()
	slice := make([]T, 0, len(set.val))
	for val := range set.val {
		slice = append(slice, val)
	}
	return slice
}

// Count count the number of values stored in set.
func (set *Set[T]) Count() int {
	set.mux.Lock()
	defer set.mux.Unlock()
	return len(set.val)
}

// IsEmpty checks if the set is empty.
func (set *Set[T]) IsEmpty() bool {
	set.mux.Lock()
	defer set.mux.Unlock()
	return len(set.val) == 0
}

// Env is the environment enum the application will run.
type Env string

// Application runtime environment.
const (
	PRD Env = "prd"
	DEV Env = "dev"
	TST Env = "tst"
)

// AccountActivity represents the account activity enum.
type AccountActivity string

const (
	// ActiveAccount represents active accounts value.
	ActiveAccount AccountActivity = "A"
	// InactiveAccount represents inactive accounts value.
	InactiveAccount AccountActivity = "I"
	// NilActivity represents a nil activity value.
	NilActivity AccountActivity = ""
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
	IsActive AccountActivity `validate:"oneof=A I ''"`
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
	Description string `json:"description" validate:"max=1000"`
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
