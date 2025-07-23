package main

import (
	"fmt"
	"isis_account/internal/config"
	"isis_account/internal/database"
	"isis_account/internal/router"
	"isis_account/internal/types"
	"net"
	"os"
	"strconv"
	"time"

	"go.uber.org/zap"
)

const (
	App     = "ISIS Account"
	Version = 0.2
)

func init() {
	// Banner
	fmt.Printf("\n%s%s %s%g%s\n\n",
		string(types.BoldBlue),
		App,
		string(types.BoldWhite),
		Version,
		string(types.Reset),
	)

	// Setup global logger
	logger := GetLogger()
	zap.ReplaceGlobals(logger)

	// Create the log's directory
	err := os.MkdirAll("logs", os.ModeDir)
	if err != nil {
		zap.L().Fatal("Could not create log directory",
			zap.Error(err),
		)
	}
}

func main() {
	// Initiate config
	cfg := config.GetConfig()

	// Initiate database
	db, err := database.GetInstance()
	for i := 1; err != nil; i++ {
		zap.L().Warn("Could not ping database ["+strconv.Itoa(i)+"]",
			zap.Error(err),
		)
		time.Sleep(3 * time.Second) // try again after 3 seconds
		db, err = database.GetInstance()
	}
	defer func() {
		err := db.Close()
		if err != nil {
			zap.L().Error("Could not close database connection",
				zap.Error(err),
			)
		}
	}()

	// New listener
	listener, err := net.Listen("tcp", ":"+strconv.Itoa(cfg.Port))
	if err != nil {
		zap.L().Fatal("Cannot start server on port "+strconv.Itoa(cfg.Port),
			zap.Error(err),
		)
	}
	cfg.Port = listener.Addr().(*net.TCPAddr).Port

	// New router and serve
	r := router.NewRouter()
	r.Listener = listener
	zap.L().Info("Serving on port " + strconv.Itoa(cfg.Port))
	r.Logger.Fatal(r.Start(":" + strconv.Itoa(cfg.Port)))
}
