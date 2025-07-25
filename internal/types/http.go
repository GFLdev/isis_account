package types

import (
	"github.com/google/uuid"
)

// SuccessMessages is the enum for HTTP success messages.
type SuccessMessages HTTPMessageResponse

// Success messages.
var (
	LoggedOut        = SuccessMessages{Message: "User logged out successfully"}
	AlreadyLoggedOut = SuccessMessages{Message: "User already logged out"}
	AccountUpdated   = SuccessMessages{Message: "Account updated successfully"}
	AccountsDeleted  = SuccessMessages{Message: "Accounts deleted successfully"}
	AccountDeleted   = SuccessMessages{Message: "Account deleted successfully"}
	RoleUpdated      = SuccessMessages{Message: "Role updated successfully"}
	RolesDeleted     = SuccessMessages{Message: "Roles deleted successfully"}
	RoleDeleted      = SuccessMessages{Message: "Role deleted successfully"}
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
	RoleID uuid.UUID `json:"role_id" validate:"omitempty,uuid"`
	// Username is the account's username.
	Username string `json:"username" validate:"omitempty,min=4,max=30"`
	// Name is the account's user first name.
	Name string `json:"name" validate:"omitempty,max=100"`
	// Surname is the account's user surname.
	Surname string `json:"surname" validate:"omitempty,max=100"`
	// Email is the account's user email.
	Email string `json:"email" validate:"omitempty,email,max=100"`
	// Password is the account's bcrypt hash.
	Password string `json:"password" validate:"omitempty,max=72"`
	// IsActive is the account's active status.
	IsActive AccountActivity `validate:"omitempty,oneof=A I ''"`
}

// HTTPDeleteAccountsForm represents the delete multiple accounts form.
type HTTPDeleteAccountsForm struct {
	// AccountsID is the accounts' ID, to be deleted, slice.
	AccountsID []uuid.UUID `json:"accounts_id" validate="required,unique,min=1,dive,required,uuid"`
}

// HTTPNewRoleForm represents the new role form.
type HTTPNewRoleForm struct {
	// Name is the role's name.
	Name string `json:"name" validate:"required,max=50"`
	// Description is the role's description.
	Description string `json:"description" validate:"max=1000"`
}

// HTTPPatchRoleForm represents the update role form.
type HTTPPatchRoleForm struct {
	// Name is the role's name.
	Name string `json:"name" validate:"omitempty,max=50"`
	// Description is the role's description.
	Description string `json:"description" validate:"omitempty,max=1000"`
}

// HTTPDeleteRolesForm represents the delete multiple roles form.
type HTTPDeleteRolesForm struct {
	// RolesID is the roles' ID, to be deleted, slice.
	RolesID []uuid.UUID `json:"roles_id" validate="required,unique,min=1,dive,required,uuid"`
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

type HTTPNonExistantAccountsResponse struct {
	NonExistantAccounts []uuid.UUID `json:"non_existant_accounts" validate="required,unique,min=1,dive,required,uuid"`
}

type HTTPNonExistantRolesResponse struct {
	NonExistantRoles []uuid.UUID `json:"non_existant_roles" validate="required,unique,min=1,dive,required,uuid"`
}

type HTTPRolesInUseResponse struct {
	RolesInUse []uuid.UUID `json:"roles_in_use" validate="required,unique,min=1,dive,required,uuid"`
}
