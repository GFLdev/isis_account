package utils

import (
	"encoding/json"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"github.com/labstack/echo/v4"
	"go.uber.org/zap"
)

// LogWithHTTPInfo is a wrapper to zap.L() to log with HTTP request/response
// information.
func LogWithHTTPInfo(
	c echo.Context,
	l func(string, ...zap.Field),
	msg string,
	fields ...zap.Field,
) {
	// Request/Response info and append fields
	e2eFields := []zap.Field{
		zap.String("method", c.Request().Method),
		zap.String("path", c.Path()),
		zap.String("client_ip", c.RealIP()),
	}
	allFields := append(e2eFields, fields...)

	// Log
	l(msg, allFields...)
}

// CloseFiles close files and warns if it couldn't. Used in defer.
func CloseFiles(files ...*os.File) {
	for _, file := range files {
		err := file.Close()
		if err != nil {
			zap.L().Warn("Could not close file.",
				zap.String("file", file.Name()),
			)
		}
	}
}

// ValidateStruct validates a struct. Return nil if it passes.
func ValidateStruct(val interface{}) error {
	validate := validator.New() // new validator instance
	return validate.Struct(val) // validate and return its result
}

// ParseHTTPBody parses body slice to a T struct.
func ParseHTTPBody[T any](body *io.ReadCloser) (T, error) {
	// Unmarshalling to JSON
	var val T
	decoder := json.NewDecoder(*body)
	decoder.DisallowUnknownFields()
	err := decoder.Decode(&val) // decodes JSON to struct
	if err != nil {
		return val, err
	}
	return val, nil
}
