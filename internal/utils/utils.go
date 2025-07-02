package utils

import (
	"encoding/json"
	"io"
	"os"

	"github.com/go-playground/validator/v10"
	"go.uber.org/zap"
)

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
