package database

import (
	"database/sql"
	"fmt"
	"isis_account/internal/utils"
	"os"
	"strconv"
	"sync"

	_ "github.com/lib/pq"
	"go.uber.org/zap"
)

// dbCredentials represents the PostgreSQL credentials required to build the
// connection string.
type dbCredentials struct {
	// host is the PostgreSQL server's hostname/ip.
	host string `validate:"required,hostname|ip"`
	// port is the PostgreSQL server's port number.
	port int `validate:"required,min=0,max=65535"`
	// user is the PostgreSQL server's username.
	user string `validate:"required,regex=^[a-zA-Z0-9_]+$"`
	// password is the PostgreSQL server's password.
	password string `validate:"required"`
	// dbname is the PostgreSQL server's database/service name.
	dbname string `validate:"required,regex=^[a-zA-Z0-9_]+$"`
}

var (
	instance *sql.DB
	once     sync.Once
)

func getCredentials() dbCredentials {
	// Validate credentials
	port, err := strconv.Atoi(os.Getenv("DB_PORT"))
	if err != nil {
		zap.L().Fatal("Could not parse DB_PORT",
			zap.Error(err),
		)
	}

	cred := dbCredentials{
		host:     os.Getenv("DB_HOST"),
		port:     port,
		user:     os.Getenv("DB_USER"),
		password: os.Getenv("DB_PASS"),
		dbname:   os.Getenv("DB_NAME"),
	}
	err = utils.ValidateStruct(cred)
	if err != nil {
		zap.L().Fatal("Invalid database credentials",
			zap.Error(err),
		)
	}

	return cred
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
		// If it cannot open the database connection, crash the program
		zap.L().Fatal("Could not connect to database",
			zap.Error(err),
		)
	}
	return db
}

// GetInstance is a singleton database connection getter.
func GetInstance() (*sql.DB, error) {
	once.Do(func() {
		cred := getCredentials()
		instance = connect(cred)
		zap.L().Info("Database connected successfully")
	})

	// Check connection
	err := instance.Ping()
	if err != nil {
		return nil, err
	}
	return instance, nil
}
