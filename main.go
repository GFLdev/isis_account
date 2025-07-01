package main

import (
	"fmt"
	"isis_account/internal/db"
	"isis_account/internal/router"
	"net/http"
	"os"
	"strconv"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
)

const (
	App     = "ISIS Account"
	Version = 0.1
)

// Serve create a new HTTP server and listen.
func Serve(port int, r *mux.Router) {
	zap.L().Info("Serving on port " + strconv.Itoa(port))
	err := http.ListenAndServe(":"+strconv.Itoa(port), r)
	if err != nil {
		zap.L().Error("Server stopped",
			zap.Error(err),
		)
	}
}

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
	// New router
	r := router.NewRouter()

	// Connect to database
	_ = db.GetInstance()

	// Parse server port and serve
	port, err := strconv.Atoi(os.Getenv("PORT"))
	if err != nil {
		zap.L().Warn("Could not parse server port, defaulting to 8080",
			zap.Error(err),
		)
		port = 8080
	}
	Serve(port, r)
}
