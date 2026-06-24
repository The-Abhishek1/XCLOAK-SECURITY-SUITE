package database

import (
	"database/sql"
	"fmt"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"xcloak-ngfw/secrets"
)

var DB *sql.DB

const (
	maxRetries  = 10
	retryDelay  = 3 * time.Second
	maxOpenConn = 25
	maxIdleConn = 5
	connLifetime = 5 * time.Minute
)

// Connect establishes a Postgres connection with retry logic so the backend
// survives docker-compose startup races (postgres container takes a few
// seconds to become healthy after the backend container starts).
func Connect() error {

	godotenv.Load()

	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable" // preserve today's behavior unless the operator opts in
	}

	// DB_PASSWORD: Vault KV at secret/data/xcloak/backend#db_password when
	// Vault is configured (see secrets.Init, called in main before this),
	// else the env var — same fallback every secret in this function uses.
	dbPassword := secrets.Resolve("DB_PASSWORD", "xcloak/backend", "db_password")

	connStr := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		dbPassword,
		os.Getenv("DB_NAME"),
		sslmode,
	)

	// lib/pq reads these directly off the DSN — only appended when set, so
	// `require` works with just a self-signed server cert and no extra config.
	if v := os.Getenv("DB_SSLROOTCERT"); v != "" {
		connStr += " sslrootcert=" + v
	}
	if v := os.Getenv("DB_SSLCERT"); v != "" {
		connStr += " sslcert=" + v
	}
	if v := os.Getenv("DB_SSLKEY"); v != "" {
		connStr += " sslkey=" + v
	}

	var db *sql.DB
	var err error

	for attempt := 1; attempt <= maxRetries; attempt++ {

		db, err = sql.Open("postgres", connStr)
		if err != nil {
			fmt.Printf("DB open error (attempt %d/%d): %v\n", attempt, maxRetries, err)
			time.Sleep(retryDelay)
			continue
		}

		if err = db.Ping(); err != nil {
			fmt.Printf("DB ping failed (attempt %d/%d): %v\n", attempt, maxRetries, err)
			db.Close()
			time.Sleep(retryDelay)
			continue
		}

		// Connected — configure pool.
		db.SetMaxOpenConns(maxOpenConn)
		db.SetMaxIdleConns(maxIdleConn)
		db.SetConnMaxLifetime(connLifetime)

		DB = db
		fmt.Println("Database connected successfully")
		return nil
	}

	return fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
}
