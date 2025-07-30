package main

import (
	"fmt"
	"isis_account/internal/config"
	"isis_account/internal/database"
	"isis_account/internal/logger"
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
	// Create the log's directory
	err := os.MkdirAll(logger.LogsDir, os.ModePerm)
	if err != nil {
		zap.L().Fatal("Could not create log directory",
			zap.Error(err),
		)
	}
}

func main() {
	// Banner
	fmt.Printf("\n%s%s %s%g%s\n\n",
		types.BoldBlue,
		App,
		types.BoldWhite,
		Version,
		types.Reset,
	)

	// Initiate config
	cfg := config.GetConfig()

	// Setup global logger
	lgr := logger.GetLogger(cfg.Env)
	defer func() { // Flush buffer
		err := lgr.Sync()
		if err != nil {
			lgr.Warn("Could not flush log entries",
				zap.Error(err),
			)
		}
	}()
	zap.ReplaceGlobals(lgr)

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
