package types

import "github.com/google/uuid"

// SuccessMessages is the enum for HTTP success messages.
type SuccessMessages string

// Success messages.
const (
	LoggedOut        SuccessMessages = "User logged out successfully"
	AlreadyLoggedOut SuccessMessages = "User already logged out"
)

// HTTPLoginForm represents the login form sent from the user.
type HTTPLoginForm struct {
	// Username is the account's username in the form.
	Username string `json:"username" validate:"required,min=4,max=30"`
	// Password is the account's password in the form.
	Password string `json:"password" validate:"required,min=4,max=16"`
}

// HTTPNewAccountForm represents the new account form.
type HTTPNewAccountForm struct {
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
	Password string `json:"password" validate:"required,max=72"`
}

// HTTPPatchAccountForm represents the update account form.
type HTTPPatchAccountForm struct {
	// RoleID is the account's role ID.
	RoleID uuid.UUID `json:"role_id" validate:"uuid"`
	// Username is the account's username.
	Username string `json:"username" validate:"min=4,max=30"`
	// Name is the account's user first name.
	Name string `json:"name" validate:"max=100"`
	// Surname is the account's user surname.
	Surname string `json:"surname" validate:"max=100"`
	// Email is the account's user email.
	Email string `json:"email" validate:"email,max=100"`
	// Password is the account's bcrypt hash.
	Password string `json:"password" validate:"max=72"`
}

// HTTPMessageResponse represents the JSON message response.
type HTTPMessageResponse struct {
	// Message is the message of the response.
	Message string `json:"message"`
}

// HTTPLoginResponse represents the data sent to the user after a successful
// login.
type HTTPLoginResponse struct {
	// AccountID is the account's ID.
	AccountID uuid.UUID `json:"account_id" validate:"required,uuid"`
	// RoleID is the role's ID of the account.
	RoleID uuid.UUID `json:"role_id" validate:"required,uuid"`
}
