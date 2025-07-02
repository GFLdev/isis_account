package main

import (
	"database/sql"
	"fmt"
	"isis_account/internal/db"
	"isis_account/internal/router"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
)

const (
	App     = "ISIS Account"
	Version = 0.1
)

func init() {
	fmt.Printf("%s %g started\n", App, Version)

	// Setup global logger
	logger := GetLogger()
	zap.ReplaceGlobals(logger)

	// Load .env
	env := os.Getenv("ENV")
	if env == "test" || env == "development" {
		err := os.Setenv("ENV", "production")
		if err != nil {
			zap.L().Fatal("Could not default ENV to production",
				zap.Error(err),
			)
		}
	}

	// Create the log's directory
	err := os.MkdirAll("logs", os.ModeDir)
	if err != nil {
		zap.L().Fatal("Could not create log directory",
			zap.Error(err),
		)
	}
}

func main() {
	// Poll to connect to database
	var dbInstance *sql.DB
	var err error
	for {
		dbInstance, err = db.GetInstance()
		if err == nil {
			zap.L().Info("Database is responding correctly")
			break
		}
		zap.L().Warn("Database not responding",
			zap.Error(err),
		)
		time.Sleep(5 * time.Second) // 5 seconds retry
	}
	defer func() {
		err := dbInstance.Close() // close database connection
		if err != nil {
			zap.L().Error("Could not close database connection",
				zap.Error(err),
			)
		}
	}()

	// New router
	r := router.NewRouter()

	// Parse server port and serve
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		zap.L().Warn("Could not parse server port, defaulting to 8080",
			zap.Error(err),
		)
		port = 8080
	}
	zap.L().Info("Serving on port " + strconv.Itoa(port))
	r.Logger.Fatal(r.Start(":" + strconv.Itoa(port)))
}
