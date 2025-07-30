package database

import (
	"database/sql"
	"fmt"
	"isis_account/internal/config"
	"sync"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

var (
	instance *sql.DB
	once     sync.Once
)

// GetInstance is a singleton database connection getter.
func GetInstance() (*sql.DB, error) {
	once.Do(func() {
		cfg := config.GetConfig()
		// TODO: implement sslmode
		connString := fmt.Sprintf(
			"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
			cfg.DB.Host,
			cfg.DB.Port,
			cfg.DB.User,
			cfg.DB.Password,
			cfg.DB.Name,
		)
		db, err := sql.Open("postgres", connString)
		if err != nil {
			// If it cannot open the database connection, crash the program
			zap.L().Fatal("Could not connect to database",
				zap.Error(err),
			)
		}
		instance = db
		zap.L().Info("Database connected successfully")
	})

	// Check connection
	err := instance.Ping()
	if err != nil {
		return nil, err
	}
	return instance, nil
}
