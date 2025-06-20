package utils

import (
	"log/slog"
	"os"
)

// CloseFiles close files and warns if it couldn't. Used in defer.
func CloseFiles(files ...*os.File) {
	for _, file := range files {
		err := file.Close()
		if err != nil {
			slog.Warn("Could not close file.", "file", file.Name())
		}
	}
}
