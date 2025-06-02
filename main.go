package main

import (
	"fmt"
	"github.com/joho/godotenv"
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
		zap.L().Error("Server stopped")
	}
}

func init() {
	fmt.Printf("%s %g started\n", App, Version)

	// Load .env
	err := godotenv.Load()
	if err != nil {
		panic("Could not load .env file: " + err.Error())
	}
	env := os.Getenv("ENV")
	if env == "tst" || env == "dev" {
		err = os.Setenv("ENV", "prd")
		if err != nil {
			panic("Could not default ENV to prd: " + err.Error())
		}
	}

	// Create the log's directory
	err = os.MkdirAll("logs", os.ModeDir)
	if err != nil {
		panic("Could not create log directory: " + err.Error())
	}

	// Setup global logger
	err = SetLogger()
	if err != nil {
		panic("Could not start logging system: " + err.Error())
	}
}

func main() {
	// New router
	r := router.NewRouter()

	// Start server
	port := 8080
	Serve(port, r)
}
