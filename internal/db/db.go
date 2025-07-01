package db

import (
	"database/sql"
	"fmt"
	"os"
	"strconv"
	"sync"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// TODO: implement go-validator
type dbCredentials struct {
	host     string
	port     int
	user     string
	password string
	dbname   string
}

var (
	instance *sql.DB
	once     sync.Once
)

func getCredentials() dbCredentials {
	port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		zap.L().Fatal("Could not parse DB_PORT",
			zap.Error(err),
		)
	}

	return dbCredentials{
		host:     os.Getenv("DB_HOST"),
		port:     port,
		user:     os.Getenv("DB_USER"),
		password: os.Getenv("DB_PASS"),
		dbname:   os.Getenv("DB_NAME"),
	}
}

// TODO: implement sslmode
func connect(cred dbCredentials) *sql.DB {
	connString := fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=disable",
		cred.host,
		cred.port,
		cred.user,
		cred.password,
		cred.dbname,
	)
	db, err := sql.Open("postgres", connString)
	if err != nil {
		zap.L().Fatal("Could not connect to database",
			zap.Error(err),
		)
	}
	return db
}

// GetInstance is a singleton database connection getter.
func GetInstance() *sql.DB {
	once.Do(func() {
		cred := getCredentials()
		instance = connect(cred)
		err := instance.Ping() // test connection
		if err != nil {
			zap.L().Fatal("Database not available",
				zap.Error(err),
			)
		}
		zap.L().Info("Database connected successfully")
	})
	return instance
}
