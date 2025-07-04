package config

import (
	"database/sql"
	"isis_account/internal/database"
	"isis_account/internal/utils"
	"strconv"
	"sync"

	"go.uber.org/zap"
)

type Config struct {
	Port int
	DB   *sql.DB
	Env  string
	JWT  struct {
		Secret             []byte
		AccessTokenMinutes int
		RefreshTokenHours  int
	}
}

var (
	instance *Config
	once     sync.Once
)

func initConfig() {
	instance = new(Config)
	var err error

	// Environment
	instance.Env = utils.MustEnv("ENV")

	// Serving port
	instance.Port, err = strconv.Atoi(utils.MustEnv("PORT"))
	if err != nil {
		zap.L().Fatal("Invalid server port",
			zap.Error(err),
		)
	}

	// Database instance
	instance.DB, err = database.GetInstance()
	if err != nil { // crashes, if it could not successfully connect to database
		zap.L().Fatal("Could not get database instance",
			zap.Error(err),
		)
	}

	// JWT config
	instance.JWT.Secret = []byte(utils.MustEnv("JWT_SECRET"))
	instance.JWT.AccessTokenMinutes, err = strconv.Atoi(utils.MustEnv("JWT_ACCESS_TOKEN_MINUTES"))
	if err != nil {
		zap.L().Fatal("Invalid JWT access token expiration in minutes",
			zap.Error(err),
		)
	}
	instance.JWT.RefreshTokenHours, err = strconv.Atoi(utils.MustEnv("JWT_REFRESH_TOKEN_HOURS"))
	if err != nil {
		zap.L().Fatal("Invalid JWT refresh token expiration in hours",
			zap.Error(err),
		)
	}
}

func GetConfig() *Config {
	once.Do(initConfig)
	return instance
}
