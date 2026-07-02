package database

import (
	"embed"
	"errors"
	"fmt"
	"log/slog"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// Migrate applies all pending up migrations from db/migrations against DB.
// Safe to call on every startup — migrate tracks applied versions in the
// schema_migrations table and no-ops once the DB is current.
//
// If the database is in a dirty state (a previous migration run was
// interrupted), Migrate forces the version to the dirty number and retries.
// The migration SQL itself is idempotent (uses CREATE TABLE IF NOT EXISTS,
// IF NOT EXISTS guards in PL/pgSQL blocks, etc.) so re-running it is safe.
func Migrate() error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("loading embedded migrations: %w", err)
	}

	driver, err := postgres.WithInstance(DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("creating migrate driver: %w", err)
	}

	m, err := migrate.NewWithInstance("iofs", source, "postgres", driver)
	if err != nil {
		return fmt.Errorf("initializing migrate: %w", err)
	}

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			return nil
		}

		// A dirty-state error looks like: "Dirty database version N. Fix and
		// force version." Force the version to clear the dirty flag and retry.
		var dirtyErr migrate.ErrDirty
		if errors.As(err, &dirtyErr) {
			slog.Warn("dirty migration state detected — rewinding and retrying",
				"dirty_version", dirtyErr.Version)
			// Force to version-1 so the dirty migration is re-run from scratch.
			// All XCloak migrations are idempotent (CREATE IF NOT EXISTS guards),
			// so re-running is safe even if the migration partially applied before
			// being interrupted.
			prev := dirtyErr.Version - 1
			if prev < 0 {
				prev = 0
			}
			if ferr := m.Force(prev); ferr != nil {
				return fmt.Errorf("forcing migration version %d: %w", prev, ferr)
			}
			// Re-run from the forced version.
			if rerr := m.Up(); rerr != nil && !errors.Is(rerr, migrate.ErrNoChange) {
				return fmt.Errorf("applying migrations after force: %w", rerr)
			}
			return nil
		}

		return fmt.Errorf("applying migrations: %w", err)
	}

	return nil
}
