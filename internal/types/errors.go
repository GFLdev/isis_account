package types

import "errors"

// HTTPError is the struct for custom HTTP errors.
type HTTPError struct {
	message string
}

// Err returns the HTTPError message as error.
func (err *HTTPError) Err() error {
	return errors.New(err.message)
}

// Message return HTTPError as HTTPMessageResponse.
func (err *HTTPError) Message() HTTPMessageResponse {
	return HTTPMessageResponse{Message: err.message}
}

// HTTP custom error.
var (
	InvalidBody               = HTTPError{message: "Invalid body"}
	ParsingError              = HTTPError{message: "Parsing Error"}
	InvalidAuthForm           = HTTPError{message: "Invalid username or password"}
	IncorrectCredentials      = HTTPError{message: "Incorrect username or password"}
	DatabaseConnectionError   = HTTPError{message: "Could not connect to database"}
	InternalError             = HTTPError{message: "Internal processing error"}
	NotFound                  = HTTPError{message: "Resource not found"}
	SessionExpired            = HTTPError{message: "Session expired"}
	NotImplemented            = HTTPError{message: "Resource not implemented yet"}
	InvalidParameters         = HTTPError{message: "Invalid parameters"}
	NoAccountsFound           = HTTPError{message: "No accounts found"}
	AccountNotFound           = HTTPError{message: "Account not found"}
	UsernameTaken             = HTTPError{message: "Username already taken"}
	InvalidNewAccountForm     = HTTPError{message: "Invalid new account form"}
	InvalidPatchAccountForm   = HTTPError{message: "Invalid update account form"}
	InvalidDeleteAccountsForm = HTTPError{message: "Invalid delete multiple accounts form"}
	NoRolesFound              = HTTPError{message: "No roles found"}
	RoleNotFound              = HTTPError{message: "Role not found"}
	RoleInUse                 = HTTPError{message: "Role is in use"}
	InvalidNewRoleForm        = HTTPError{message: "Invalid new role form"}
	InvalidPatchRoleForm      = HTTPError{message: "Invalid update role form"}
	InvalidDeleteRolesForm    = HTTPError{message: "Invalid delete multiple roles form"}
	RoleNotElevated           = HTTPError{message: "Role is not elevated for given module"}
	TokenError                = HTTPError{message: "Could not get token"}
	ParseTokenError           = HTTPError{message: "Could not parse token"}
	ClaimsError               = HTTPError{message: "Could not parse token claims"}
	AuthFailedError           = HTTPError{message: "Authentication failed"}
	InvalidClaimsData         = HTTPError{message: "Token data is not valid"}
)
