package main

import (
	"go.uber.org/zap"
)

func GetLogger() *zap.Logger {
	logger, _ := zap.NewProduction()
	defer logger.Sync()
	return logger
}
