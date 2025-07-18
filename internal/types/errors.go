package types

import "errors"

// HTTPError is the enum for HTTP error messages.
type HTTPError error

var (
	ParsingError            HTTPError = errors.New("Parsing Error")
	InvalidAuthForm         HTTPError = errors.New("Invalid username or password")
	IncorrectCredentials    HTTPError = errors.New("Incorrect username or password")
	DatabaseConnectionError HTTPError = errors.New("Could not connect to database")
	InternalError           HTTPError = errors.New("Internal processing error")
	AccountNotFound         HTTPError = errors.New("Account not found")
	NotFound                HTTPError = errors.New("Resource not found")
	SessionExpired          HTTPError = errors.New("Session expired")
	NotImplemented          HTTPError = errors.New("Resource not implemented yet")
)

// AuthError is enum for authentication errors.
type AuthError error

var (
	TokenError      AuthError = errors.New("Could not get token")
	ParseTokenError AuthError = errors.New("Could not parse token")
	ClaimsError     AuthError = errors.New("Could not parse token claims")
	AuthFailedError AuthError = errors.New("Authentication failed")
)
