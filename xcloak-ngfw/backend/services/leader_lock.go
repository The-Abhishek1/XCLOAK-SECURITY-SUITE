package services

import (
	"fmt"
	"hash/fnv"

	"xcloak-ngfw/database"
)

func lockKey(name string) int64 {
	h := fnv.New64a()
	h.Write([]byte(name))
	return int64(h.Sum64())
}

// WithSingletonLock runs fn only if this process wins a Postgres
// transaction-scoped advisory lock for name, then releases the lock when fn
// returns. If another backend replica currently holds the lock for name,
// fn is skipped entirely for this tick rather than queued — the job just
// runs on whichever replica wins next time.
//
// This exists because several background jobs (audit export, scheduled-task
// dispatch, health scoring, KEV refresh, offline-agent marking) were
// originally written assuming exactly one backend process ever runs them —
// safe with a single replica, but silently double-dispatching/double-exporting
// the moment a second replica is added for HA. pg_try_advisory_xact_lock is
// used (not the session-scoped pg_try_advisory_lock) specifically so the lock
// is released automatically when this transaction ends, regardless of which
// pooled connection database/sql happens to hand back — no risk of leaking a
// held lock on connection reuse.
//
// Deliberately NOT used for RefreshMetrics: Prometheus scrapes each replica's
// /metrics endpoint independently (per-pod, not through the Service VIP), so
// every replica must keep computing its own in-process gauges. Locking that
// one would starve every non-leader replica's /metrics of real data.
func WithSingletonLock(name string, fn func()) {
	tx, err := database.DB.Begin()
	if err != nil {
		fmt.Printf("[singleton-lock] %s: begin tx failed: %v\n", name, err)
		return
	}
	defer tx.Rollback()

	var acquired bool
	if err := tx.QueryRow(`SELECT pg_try_advisory_xact_lock($1)`, lockKey(name)).Scan(&acquired); err != nil {
		fmt.Printf("[singleton-lock] %s: lock query failed: %v\n", name, err)
		return
	}
	if !acquired {
		return
	}

	fn()
}
