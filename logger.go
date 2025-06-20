package main

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// GetLogger gets a new configured multiplexed logger instance.
// Default config: production
func GetLogger() *zap.Logger {
	ts := strconv.FormatInt(time.Now().Unix(), 10) // timestamp

	// Logging outputs
	consoleWriter := zapcore.Lock(os.Stdout)
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   filepath.Join("logs", ts+".json"),
		MaxSize:    20, // megabytes
		MaxBackups: 3,
		MaxAge:     7, // days
	})

	// Encoders
	var consoleConfig, fileConfig zapcore.EncoderConfig
	var level zapcore.Level

	if os.Getenv("ENV") == "development" {
		level = zapcore.DebugLevel
		consoleConfig = zap.NewDevelopmentEncoderConfig()
		fileConfig = zap.NewDevelopmentEncoderConfig()
	} else if os.Getenv("ENV") == "test" {
		level = zapcore.ErrorLevel
		consoleConfig = zap.NewDevelopmentEncoderConfig()
		fileConfig = zap.NewDevelopmentEncoderConfig()
	} else {
		level = zapcore.InfoLevel
		consoleConfig = zap.NewProductionEncoderConfig()
		fileConfig = zap.NewProductionEncoderConfig()
	}

	consoleConfig.TimeKey = "timestamp"
	fileConfig.TimeKey = "timestamp"

	consoleConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	fileConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	consoleConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder

	consoleEncoder := zapcore.NewConsoleEncoder(consoleConfig)
	fileEncoder := zapcore.NewJSONEncoder(fileConfig)

	// Multiplexed core
	core := zapcore.NewTee(
		zapcore.NewCore(consoleEncoder, consoleWriter, level),
		zapcore.NewCore(fileEncoder, fileWriter, level),
	)
	logger := zap.New(core, zap.AddCaller(), zap.AddCallerSkip(1))

	// Flush buffer and return
	defer func() {
		err := logger.Sync()
		if err != nil {
			logger.Warn("Could not flush log entries",
				zap.Error(err),
			)
		}
	}()
	return logger
}
