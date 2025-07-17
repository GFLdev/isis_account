package config

import (
	"bytes"
	"isis_account/internal/utils"
	"os"
	"sync"

	"go.uber.org/zap"
)

type Env string

const (
	PRD Env = "prd"
	DEV Env = "dev"
	TST Env = "test"
)

const (
	ConfigFile = "config.json"
)

type Config struct {
	// Env is the environment that ISIS Account will be running.
	Env Env `json:"env" validate:"oneof=prd dev tst"`
	// Port is the port that ISIS Account will be running.
	Port int `json:"port" validate:"min=0,max=65535"`
	// Origins are the origins for handling CORS.
	Origins []string `json:"origins" validate:"dive,unique"`
	// DB represents the PostgreSQL database credentials.
	DB struct {
		// Host is the PostgreSQL server's hostname/ip.
		Host string `json:"host" validate:"required,hostname|ip"`
		// Port is the PostgreSQL server's port number.
		Port int `json:"port" validate:"required,min=0,max=65535"`
		// User is the PostgreSQL server's username.
		User string `json:"user" validate:"required"`
		// Password is the PostgreSQL server's password.
		Password string `json:"password" validate:"required"`
		// Name is the PostgreSQL server's database/service name.
		Name string `json:"name" validate:"required"`
	} `json:"db" validate:"required"`
	// JWT represents the JWT configuration.
	JWT struct {
		// Secret is the JWT secret.
		Secret string `json:"secret" validate:"required,min=32"`
		// AccessTokenMinutes is the access token's expiration time in minutes.
		AccessTokenMinutes int `json:"access_token_minutes"`
		// RefreshTokenHours is the refresh token's expiration time in hours.
		RefreshTokenHours int `json:"refresh_token_hours"`
	} `json:"jwt" validate:"required"`
}

var (
	instance *Config
	once     sync.Once
)

func initConfig() {
	// Read configuration file
	file, err := os.Open(ConfigFile)
	if err != nil {
		zap.L().Fatal("Config file '"+ConfigFile+"' not found",
			zap.Error(err),
		)
	}
	payload, err := utils.ReadFile(file)
	if err != nil {
		zap.L().Fatal("Could not read config file '"+ConfigFile+"'",
			zap.Error(err),
		)
	}

	// Parse configuration
	reader := bytes.NewReader(*payload)
	cfg, err := utils.JSONToStruct[Config](reader)
	if err != nil {
		zap.L().Fatal("Could not parse config file '"+ConfigFile+"'",
			zap.Error(err),
		)
	}

	// Validate fields
	err = utils.ValidateStruct(cfg)
	if err != nil {
		zap.L().Fatal("Invalid configuration values",
			zap.Error(err),
		)
	}

	// Default optional values
	if cfg.Env == "" {
		zap.L().Info("Defaulting environment to 'tst'")
		cfg.Env = TST // Default to test environment
	}
	if len(cfg.Origins) == 0 {
		zap.L().Info("Defaulting allowed origins to '*'")
		cfg.Origins = []string{"*"} // Default to all origins
	}
	if cfg.JWT.AccessTokenMinutes == 0 {
		zap.L().Info("Defaulting access token expiration to 30 minutes")
		cfg.JWT.AccessTokenMinutes = 30 // Default to 30 minutes
	}
	if cfg.JWT.RefreshTokenHours == 0 {
		zap.L().Info("Defaulting refresh token expiration to 24 hours")
		cfg.JWT.RefreshTokenHours = 24 // Default to 24 hours
	}
	instance = &cfg
}

func GetConfig() *Config {
	once.Do(initConfig)
	return instance
}
