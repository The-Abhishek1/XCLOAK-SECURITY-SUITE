package database

// DB circuit breaker — monitors primary and replica health every 30 seconds,
// transitions through closed → open → half-open states, and exposes a
// flag the HTTP middleware can use to return 503 before a DB call is even
// attempted.
//
// State machine:
//
//	closed    — DB is healthy; all requests proceed normally.
//	open      — DB is unreachable; middleware returns 503 with Retry-After.
//	half-open — One probe is in-flight; subsequent requests still get 503
//	            until the probe succeeds and the circuit re-closes.
//
// Thresholds (tunable via env at startup):
//
//	CIRCUIT_FAIL_THRESHOLD  — consecutive failures before opening (default 3)
//	CIRCUIT_PROBE_INTERVAL  — seconds between probes in open state (default 15)
//	CIRCUIT_MONITOR_INTERVAL — seconds between health checks in closed state (default 30)

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type circuitState int32

const (
	stateClosed   circuitState = 0
	stateOpen     circuitState = 1
	stateHalfOpen circuitState = 2
)

var (
	primaryState       atomic.Int32
	replicaState       atomic.Int32
	primaryFailCount   atomic.Int32
	replicaFailCount   atomic.Int32
	lastPrimaryFailure time.Time
	lastReplicaFailure time.Time
	cbMu               sync.RWMutex

	failThreshold    = 3
	probeInterval    = 15 * time.Second
	monitorInterval  = 30 * time.Second
)

func init() {
	if v := os.Getenv("CIRCUIT_FAIL_THRESHOLD"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			failThreshold = n
		}
	}
	if v := os.Getenv("CIRCUIT_PROBE_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			probeInterval = time.Duration(n) * time.Second
		}
	}
	if v := os.Getenv("CIRCUIT_MONITOR_INTERVAL"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			monitorInterval = time.Duration(n) * time.Second
		}
	}
}

// StartCircuitBreaker launches the background monitor. Call once from main
// after database.Connect() succeeds.
func StartCircuitBreaker() {
	go runMonitor()
}

// IsPrimaryDown returns true when the circuit for the primary DB is open or
// half-open. The HTTP middleware uses this to return 503 without attempting
// a query that will block and timeout.
func IsPrimaryDown() bool {
	return circuitState(primaryState.Load()) != stateClosed
}

// IsReplicaDown returns true when the read-replica circuit is not closed.
func IsReplicaDown() bool {
	if ReadDB == nil {
		return false // no replica configured — not "down"
	}
	return circuitState(replicaState.Load()) != stateClosed
}

// CircuitHealth is returned by the health endpoint.
type CircuitHealth struct {
	PrimaryState     string     `json:"primary_state"`
	ReplicaState     string     `json:"replica_state,omitempty"`
	PrimaryFailCount int        `json:"primary_fail_count"`
	ReplicaFailCount int        `json:"replica_fail_count,omitempty"`
	LastPrimaryFail  *time.Time `json:"last_primary_failure,omitempty"`
	LastReplicaFail  *time.Time `json:"last_replica_failure,omitempty"`
}

func GetCircuitHealth() CircuitHealth {
	cbMu.RLock()
	lpf := lastPrimaryFailure
	lrf := lastReplicaFailure
	cbMu.RUnlock()

	h := CircuitHealth{
		PrimaryState:     stateName(circuitState(primaryState.Load())),
		PrimaryFailCount: int(primaryFailCount.Load()),
	}
	if !lpf.IsZero() {
		h.LastPrimaryFail = &lpf
	}
	if ReadDB != nil {
		h.ReplicaState = stateName(circuitState(replicaState.Load()))
		h.ReplicaFailCount = int(replicaFailCount.Load())
		if !lrf.IsZero() {
			h.LastReplicaFail = &lrf
		}
	}
	return h
}

func stateName(s circuitState) string {
	switch s {
	case stateClosed:
		return "closed"
	case stateOpen:
		return "open"
	case stateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}

func runMonitor() {
	ticker := time.NewTicker(monitorInterval)
	defer ticker.Stop()
	for range ticker.C {
		checkPrimary()
		checkReplica()
	}
}

func checkPrimary() {
	if DB == nil {
		return
	}
	state := circuitState(primaryState.Load())

	// In open state, wait for probe interval before attempting half-open.
	if state == stateOpen {
		cbMu.RLock()
		since := time.Since(lastPrimaryFailure)
		cbMu.RUnlock()
		if since < probeInterval {
			return
		}
		primaryState.CompareAndSwap(int32(stateOpen), int32(stateHalfOpen))
	}

	if err := DB.Ping(); err != nil {
		recordFailure(&primaryFailCount, &lastPrimaryFailure, &primaryState, "primary", err)
		return
	}
	// Successful ping — reset.
	recordSuccess(&primaryFailCount, &primaryState, "primary")
}

func checkReplica() {
	if ReadDB == nil {
		return
	}
	state := circuitState(replicaState.Load())
	if state == stateOpen {
		cbMu.RLock()
		since := time.Since(lastReplicaFailure)
		cbMu.RUnlock()
		if since < probeInterval {
			return
		}
		replicaState.CompareAndSwap(int32(stateOpen), int32(stateHalfOpen))
	}

	if err := ReadDB.Ping(); err != nil {
		recordFailure(&replicaFailCount, &lastReplicaFailure, &replicaState, "replica", err)
		return
	}
	recordSuccess(&replicaFailCount, &replicaState, "replica")
}

func recordFailure(count *atomic.Int32, lastFail *time.Time, state *atomic.Int32, label string, err error) {
	n := count.Add(1)
	cbMu.Lock()
	*lastFail = time.Now()
	cbMu.Unlock()

	if int(n) >= failThreshold {
		old := state.Swap(int32(stateOpen))
		if circuitState(old) != stateOpen {
			fmt.Printf("[CircuitBreaker] %s circuit OPENED after %d failures: %v\n", label, n, err)
		}
	} else {
		fmt.Printf("[CircuitBreaker] %s ping failed (%d/%d): %v\n", label, n, failThreshold, err)
	}
}

func recordSuccess(count *atomic.Int32, state *atomic.Int32, label string) {
	old := state.Swap(int32(stateClosed))
	if circuitState(old) != stateClosed {
		fmt.Printf("[CircuitBreaker] %s circuit CLOSED (recovered)\n", label)
	}
	count.Store(0)
}

// ReplicaLagSeconds queries the replica for its replication lag in seconds.
// Returns -1 if the replica is not configured or the query fails.
func ReplicaLagSeconds() float64 {
	if ReadDB == nil || IsReplicaDown() {
		return -1
	}
	var lag *float64
	err := ReadDB.QueryRow(
		`SELECT EXTRACT(epoch FROM (NOW() - pg_last_xact_replay_timestamp()))`,
	).Scan(&lag)
	if err != nil || lag == nil {
		return -1
	}
	return *lag
}
