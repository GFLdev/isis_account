package types

import "errors"

// HTTPError is the enum for custom HTTP errors.
type HTTPError error

// HTTP custom error.
var (
	ParsingError            HTTPError = errors.New("Parsing Error")
	InvalidAuthForm         HTTPError = errors.New("Invalid username or password")
	IncorrectCredentials    HTTPError = errors.New("Incorrect username or password")
	DatabaseConnectionError HTTPError = errors.New("Could not connect to database")
	InternalError           HTTPError = errors.New("Internal processing error")
	NotFound                HTTPError = errors.New("Resource not found")
	SessionExpired          HTTPError = errors.New("Session expired")
	NotImplemented          HTTPError = errors.New("Resource not implemented yet")
	InvalidParameters       HTTPError = errors.New("Invalid parameters")
	NoAccountsFound         HTTPError = errors.New("No accounts found")
	AccountNotFound         HTTPError = errors.New("Account not found")
	UsernameTaken           HTTPError = errors.New("Username already taken")
	InvalidNewAccountForm   HTTPError = errors.New("Invalid new account form")
	NoRolesFound            HTTPError = errors.New("No roles found")
	RoleNotFound            HTTPError = errors.New("Role not found")
	RoleNotElevated         HTTPError = errors.New("Role is not elevated for given module")
)

// AuthError is enum for authentication errors.
type AuthError error

// Authentication error.
var (
	TokenError        AuthError = errors.New("Could not get token")
	ParseTokenError   AuthError = errors.New("Could not parse token")
	ClaimsError       AuthError = errors.New("Could not parse token claims")
	AuthFailedError   AuthError = errors.New("Authentication failed")
	InvalidClaimsData AuthError = errors.New("Token data is not valid")
)
