package main

import (
	"go.uber.org/zap"
	"os"
)

// SetLogger sets a new global logger instance.
func SetLogger() error {
	// Declaring logger
	var logger *zap.Logger
	var err error

	// Defining logger based on the running environment
	switch os.Getenv("ENV") {
	case "dev":
		logger, err = zap.NewDevelopment()
	case "tst":
		logger, err = zap.NewDevelopment()
	case "prd":
	default:
		logger, err = zap.NewProduction()
	}

	// Panic on error
	if err != nil {
		return err
	}

	// Flush buffer
	defer func() {
		err = logger.Sync()
		if err != nil {
			logger.Warn("Could not flush log entries.",
				zap.Error(err),
			)
		}
	}()

	// Set to global
	zap.ReplaceGlobals(logger)
	return nil
}
