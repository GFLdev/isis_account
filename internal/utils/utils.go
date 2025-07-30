package utils

import (
	"bufio"
	"database/sql"
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

// ReadFile read file using 1KB buffer, and return its content.
func ReadFile(file *os.File) (*[]byte, error) {
	data := []byte{}
	reader := bufio.NewReader(file)
	buf := make([]byte, 1024) // 1MB
	for {
		n, err := reader.Read(buf)
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		data = append(data, buf[:n]...)
	}
	return &data, nil
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
func ValidateStruct(val any) error {
	// New validator and implement custom validations
	validate := validator.New()
	validate.RegisterValidation("ip_with_localhost", ValidateIPWithLocalHost)

	// Validate
	return validate.Struct(val)
}

// JSONToStruct parses JSON io.Reader to T struct.
func JSONToStruct[T any](r io.Reader, allowUnknownFields bool) (T, error) {
	// Unmarshalling to JSON
	var val T
	decoder := json.NewDecoder(r)
	if !allowUnknownFields {
		decoder.DisallowUnknownFields()
	}
	err := decoder.Decode(&val) // decodes JSON to struct
	if err != nil {
		return val, err
	}
	return val, nil
}

// Rollback is a transaction rollback wrapper function.
func Rollback(tx *sql.Tx) {
	err := tx.Rollback()
	if err != nil && err != sql.ErrTxDone {
		zap.L().Error(
			"Could not rollback transaction",
			zap.Error(err),
		)
	}
}
