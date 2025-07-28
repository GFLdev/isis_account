package config

import (
	"bytes"
	"isis_account/internal/types"
	"isis_account/internal/utils"
	"os"
	"sync"
)

const (
	ConfigFile = "config.json"
)

type Config struct {
	// Env is the environment that ISIS Account will be running.
	Env types.Env `json:"env" validate:"oneof=prd dev tst"`
	// Port is the port that ISIS Account will be running.
	Port int `json:"port" validate:"min=0,max=65535"`
	// Origins are the origins for handling CORS.
	Origins []string `json:"origins" validate:"unique"`
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
		panic("Config file '" + ConfigFile + "' not found: " + err.Error())
	}
	payload, err := utils.ReadFile(file)
	if err != nil {
		panic("Could not read config file '" + ConfigFile + "': " + err.Error())
	}

	// Parse configuration
	reader := bytes.NewReader(*payload)
	cfg, err := utils.JSONToStruct[Config](reader, true)
	if err != nil {
		panic("Could not parse config file '" + ConfigFile + "': " + err.Error())
	}

	// Validate fields
	err = utils.ValidateStruct(cfg)
	if err != nil {
		panic("Invalid configuration values: " + err.Error())
	}

	// Default optional values
	if cfg.Env == "" {
		cfg.Env = types.PRD // Default to prd environment
	}
	if len(cfg.Origins) == 0 {
		cfg.Origins = []string{"*"} // Default to all origins
	}
	if cfg.JWT.AccessTokenMinutes == 0 {
		cfg.JWT.AccessTokenMinutes = 30 // Default to 30 minutes
	}
	if cfg.JWT.RefreshTokenHours == 0 {
		cfg.JWT.RefreshTokenHours = 24 // Default to 24 hours
	}
	instance = &cfg
}

func GetConfig() *Config {
	once.Do(initConfig)
	return instance
}
