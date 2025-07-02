package router

// ErrorMessage is the enum for HTTP error messages.
type ErrorMessage string

const (
	ParsingError            ErrorMessage = "Parsing Error"
	InvalidAuthForm         ErrorMessage = "Invalid username or password"
	IncorrectCredentials    ErrorMessage = "Incorrect username or password"
	DatabaseConnectionError ErrorMessage = "Could not connect to database"
	InternalError           ErrorMessage = "Internal processing error"
)
