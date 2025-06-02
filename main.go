package main

import (
	"fmt"
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
func Serve(addr string, port int, r *mux.Router, logger *zap.Logger) {
	logger.Info("Server started",
		zap.String("address", addr),
		zap.Int("port", port),
	)
	http.ListenAndServe(addr+strconv.Itoa(port), r)
}

func init() {
	// Create log directory
	err := os.MkdirAll("logs", os.ModeDir)
	if err != nil {
		fmt.Println("Could not create log directory: %w", err)
	}
}

func main() {
	// Set logger
	logger := GetLogger()
	logger.Info(App+" started", zap.Float64("version", Version))

	// New router
	r := router.NewRouter()

	// Start server
	port := 8080
	addr := ":"
	Serve(addr, port, r, logger)
}
