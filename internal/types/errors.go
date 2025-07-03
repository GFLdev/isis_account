package types

// HTTPErrorMessage is the enum for HTTP error messages.
type HTTPErrorMessage string

const (
	ParsingError            HTTPErrorMessage = "Parsing Error"
	InvalidAuthForm         HTTPErrorMessage = "Invalid username or password"
	IncorrectCredentials    HTTPErrorMessage = "Incorrect username or password"
	DatabaseConnectionError HTTPErrorMessage = "Could not connect to database"
	InternalError           HTTPErrorMessage = "Internal processing error"
	AccountNotFound         HTTPErrorMessage = "Account not found"
)
