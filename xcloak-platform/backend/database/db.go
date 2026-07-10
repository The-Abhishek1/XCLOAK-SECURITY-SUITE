package database

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/joho/godotenv"
	_ "github.com/lib/pq"

	"xcloak-platform/secrets"
)

// DB is the primary application connection pool. In production it connects as
// the limited-privilege APP_DB_USER role (xcloak_app) which is subject to
// PostgreSQL Row-Level Security. When APP_DB_USER is not set it falls back to
// DB_USER (existing behaviour — backwards-compatible).
var DB *sql.DB

// MigrationDB is a privileged connection used only by the migration runner.
// It connects as DB_USER (the schema owner) which has DDL rights and bypasses
// RLS — required for golang-migrate to run CREATE TABLE / ALTER TABLE etc.
// When APP_DB_USER is not configured, MigrationDB == DB (same pool, same user).
var MigrationDB *sql.DB

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
//
// Two env vars control the database user:
//   - DB_USER / DB_PASSWORD — the schema owner used for migrations (DDL rights)
//   - APP_DB_USER / APP_DB_PASSWORD — the limited-privilege application role
//     (recommended: xcloak_app, which is subject to RLS policies). Falls back
//     to DB_USER when not set so existing deployments require no changes.
func Connect() error {
	godotenv.Load()

	sslmode := os.Getenv("DB_SSLMODE")
	if sslmode == "" {
		sslmode = "disable"
	}

	// Resolve the application-pool credentials. APP_DB_USER/APP_DB_PASSWORD
	// are used when set; otherwise fall back to the owner credentials.
	appUser := os.Getenv("APP_DB_USER")
	if appUser == "" {
		appUser = os.Getenv("DB_USER")
	}
	appPassword := os.Getenv("APP_DB_PASSWORD")
	if appPassword == "" {
		appPassword = secrets.Resolve("DB_PASSWORD", "xcloak/backend", "db_password")
	}
	if appPassword == "change_me_in_production" {
		slog.Warn("SECURITY: APP_DB_PASSWORD is set to the insecure default. " +
			"Change it before deploying to production.")
	}

	connStr := buildConnStr(
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		appUser,
		appPassword,
		os.Getenv("DB_NAME"),
		sslmode,
	)

	var db *sql.DB
	var err error
	for attempt := 1; attempt <= maxRetries; attempt++ {
		db, err = sql.Open("postgres", connStr)
		if err != nil {
			slog.Warn("db: open failed", "attempt", attempt, "max", maxRetries, "err", err)
			time.Sleep(retryDelay)
			continue
		}
		if err = db.Ping(); err != nil {
			slog.Warn("db: ping failed", "attempt", attempt, "max", maxRetries, "err", err)
			db.Close()
			time.Sleep(retryDelay)
			continue
		}
		db.SetMaxOpenConns(maxOpenConn)
		db.SetMaxIdleConns(maxIdleConn)
		db.SetConnMaxLifetime(connLifetime)
		DB = db
		slog.Info("db: connected", "user", appUser)
		break
	}
	if DB == nil {
		return fmt.Errorf("failed to connect to database after %d attempts: %w", maxRetries, err)
	}

	// Open a separate privileged pool for the migration runner when APP_DB_USER
	// differs from DB_USER. The migration runner needs DDL rights (CREATE TABLE,
	// ALTER TABLE, etc.) that xcloak_app does not have. When APP_DB_USER is not
	// set, both pools use the same credentials and MigrationDB == DB.
	if ownerUser := os.Getenv("DB_USER"); ownerUser != "" && ownerUser != appUser {
		ownerPw := secrets.Resolve("DB_PASSWORD", "xcloak/backend", "db_password")
		migConnStr := buildConnStr(
			os.Getenv("DB_HOST"), os.Getenv("DB_PORT"),
			ownerUser, ownerPw,
			os.Getenv("DB_NAME"), sslmode,
		)
		if migDB, merr := sql.Open("postgres", migConnStr); merr == nil {
			if merr = migDB.Ping(); merr == nil {
				migDB.SetMaxOpenConns(3) // migration is single-threaded
				migDB.SetMaxIdleConns(1)
				migDB.SetConnMaxLifetime(connLifetime)
				MigrationDB = migDB
				slog.Info("db: migration pool connected", "owner_user", ownerUser)
			} else {
				migDB.Close()
				slog.Warn("db: migration pool ping failed, falling back to app pool", "err", merr)
			}
		}
	}
	if MigrationDB == nil {
		MigrationDB = DB
	}

	return nil
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
	slog.Info("db: read replica connected", "host", readHost)
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
