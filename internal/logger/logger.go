package logger

import (
	"isis_account/internal/types"
	"os"
	"path/filepath"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

// LogsDir is the logs directory.
const LogsDir = "logs"

// GetLogger gets a new configured multiplexed logger instance.
// Default config: production (prd)
func GetLogger(env types.Env) *zap.Logger {
	ts := time.Now().Format("20060102150405") // timestamp "YYYYMMDDHHmmSS"

	// Logging outputs
	filename := string(env) + "_" + ts + ".json"
	consoleWriter := zapcore.Lock(os.Stdout)
	fileWriter := zapcore.AddSync(&lumberjack.Logger{
		Filename:   filepath.Join(LogsDir, filename),
		MaxSize:    20, // megabytes
		MaxBackups: 3,  // maximum backup numbers
		MaxAge:     7,  // days
	})

	// Encoders
	var consoleConfig, fileConfig zapcore.EncoderConfig
	var level zapcore.Level

	if env == types.DEV {
		level = zapcore.DebugLevel
		consoleConfig = zap.NewDevelopmentEncoderConfig()
		fileConfig = zap.NewDevelopmentEncoderConfig()
	} else if env == types.TST {
		level = zapcore.WarnLevel
		consoleConfig = zap.NewDevelopmentEncoderConfig()
		fileConfig = zap.NewDevelopmentEncoderConfig()
	} else { // default: PRD
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
	return logger
}
