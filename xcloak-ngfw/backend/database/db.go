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

// DB is the primary (read-write) database connection.
var DB *sql.DB

// ReadDB is the read-replica connection. Nil when DB_READ_HOST is not set,
// in which case RDB() falls back to DB so callers need no nil checks.
var ReadDB *sql.DB

// RDB returns the read-replica connection when available, otherwise the
// primary. Use this for read-only queries (analytics, dashboard, reports)
// to offload the primary when a replica is configured.
func RDB() *sql.DB {
	if ReadDB != nil {
		return ReadDB
	}
	return DB
}

const (
	maxRetries   = 10
	retryDelay   = 3 * time.Second
	maxOpenConn  = 25
	maxIdleConn  = 5
	connLifetime = 5 * time.Minute

	// Read replica uses a larger pool — analytics queries are long-lived but
	// read-only, so more concurrency is safe.
	readMaxOpenConn  = 40
	readMaxIdleConn  = 10
	readConnLifetime = 10 * time.Minute
)

// Connect establishes the primary Postgres connection with retry logic so the
// backend survives docker-compose startup races.
func Connect() error {
	godotenv.Load()

	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	dbPassword := secrets.Resolve("DB_PASSWORD", "xcloak/backend", "db_password")

	connStr := buildConnStr(
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		dbPassword,
		os.Getenv("DB_NAME"),
		sslmode,
	)

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
		db.SetMaxOpenConns(maxOpenConn)
		db.SetMaxIdleConns(maxIdleConn)
		db.SetConnMaxLifetime(connLifetime)
		DB = db
		fmt.Println("Database connected successfully")
		return nil
	}
	return fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
}

// ConnectReadReplica attempts to connect to a Postgres read replica using
// DB_READ_HOST (all other credentials fall back to the primary env vars).
// If DB_READ_HOST is empty the function returns nil — callers treat this as
// "no replica configured" and RDB() falls back to the primary.
func ConnectReadReplica() error {
	readHost := os.Getenv("DB_READ_HOST")
	if readHost == "" {
		return nil // not configured — no-op
	}

	port := os.Getenv("DB_READ_PORT")
	if port == "" {
		port = os.Getenv("DB_PORT")
	}
	user := os.Getenv("DB_READ_USER")
	if user == "" {
		user = os.Getenv("DB_USER")
	}
	password := secrets.Resolve("DB_READ_PASSWORD", "xcloak/backend", "db_read_password")
	if password == "" {
		password = secrets.Resolve("DB_PASSWORD", "xcloak/backend", "db_password")
	}
	dbName := os.Getenv("DB_NAME")
	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	connStr := buildConnStr(readHost, port, user, password, dbName, sslmode)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		return fmt.Errorf("read replica open: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return fmt.Errorf("read replica ping: %w", err)
	}
	db.SetMaxOpenConns(readMaxOpenConn)
	db.SetMaxIdleConns(readMaxIdleConn)
	db.SetConnMaxLifetime(readConnLifetime)
	ReadDB = db
	fmt.Printf("Read replica connected (%s)\n", readHost)
	return nil
}

// DBStats returns runtime pool statistics for health reporting.
type DBStats struct {
	OpenConnections int           `json:"open_connections"`
	InUse           int           `json:"in_use"`
	Idle            int           `json:"idle"`
	WaitCount       int64         `json:"wait_count"`
	WaitDuration    time.Duration `json:"wait_duration_ns"`
	MaxOpenConns    int           `json:"max_open_conns"`
}

func PrimaryStats() DBStats { return toStats(DB) }
func ReplicaStats() DBStats { return toStats(ReadDB) }

func toStats(db *sql.DB) DBStats {
	if db == nil {
		return DBStats{}
	}
	s := db.Stats()
	return DBStats{
		OpenConnections: s.OpenConnections,
		InUse:           s.InUse,
		Idle:            s.Idle,
		WaitCount:       s.WaitCount,
		WaitDuration:    s.WaitDuration,
		MaxOpenConns:    db.Stats().MaxOpenConnections,
	}
}

func buildConnStr(host, port, user, password, dbname, sslmode string) string {
	s := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		host, port, user, password, dbname, sslmode,
	)
	if v := os.Getenv("DB_SSLROOTCERT"); v != "" {
		s += " sslrootcert=" + v
	}
	if v := os.Getenv("DB_SSLCERT"); v != "" {
		s += " sslcert=" + v
	}
	if v := os.Getenv("DB_SSLKEY"); v != "" {
		s += " sslkey=" + v
	}
	return s
}
