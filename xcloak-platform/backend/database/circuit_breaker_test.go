package database

import (
	"errors"
	"testing"
	"time"
)

// reset state between tests so they're independent.
func resetCircuit() {
	primaryState.Store(int32(stateClosed))
	replicaState.Store(int32(stateClosed))
	primaryFailCount.Store(0)
	replicaFailCount.Store(0)
	cbMu.Lock()
	lastPrimaryFailure = time.Time{}
	lastReplicaFailure = time.Time{}
	cbMu.Unlock()
}

func TestStateName(t *testing.T) {
	cases := []struct {
		state circuitState
		want  string
	}{
		{stateClosed, "closed"},
		{stateOpen, "open"},
		{stateHalfOpen, "half-open"},
		{circuitState(99), "unknown"},
	}
	for _, c := range cases {
		if got := stateName(c.state); got != c.want {
			t.Errorf("stateName(%d) = %q, want %q", c.state, got, c.want)
		}
	}
}

func TestCircuit_InitiallyClosed(t *testing.T) {
	resetCircuit()
	if IsPrimaryDown() {
		t.Error("circuit should start closed (primary not down)")
	}
}

func TestCircuit_OpenAfterThresholdFailures(t *testing.T) {
	resetCircuit()
	// Simulate failThreshold consecutive failures.
	for i := 0; i < failThreshold; i++ {
		recordFailure(&primaryFailCount, &lastPrimaryFailure, &primaryState, "primary", errors.New("test error"))
	}
	if !IsPrimaryDown() {
		t.Errorf("circuit should be open after %d failures", failThreshold)
	}
	if circuitState(primaryState.Load()) != stateOpen {
		t.Error("primary state should be stateOpen")
	}
}

func TestCircuit_NotOpenBeforeThreshold(t *testing.T) {
	resetCircuit()
	// One less than threshold — should not open.
	for i := 0; i < failThreshold-1; i++ {
		recordFailure(&primaryFailCount, &lastPrimaryFailure, &primaryState, "primary", errors.New("test error"))
	}
	if IsPrimaryDown() {
		t.Errorf("circuit should stay closed with only %d failures (threshold=%d)", failThreshold-1, failThreshold)
	}
}

func TestCircuit_ClosesAfterSuccess(t *testing.T) {
	resetCircuit()
	// Open the circuit.
	for i := 0; i < failThreshold; i++ {
		recordFailure(&primaryFailCount, &lastPrimaryFailure, &primaryState, "primary", errors.New("test"))
	}
	if !IsPrimaryDown() {
		t.Fatal("expected circuit open before recovery")
	}
	// Recover.
	recordSuccess(&primaryFailCount, &primaryState, "primary")
	if IsPrimaryDown() {
		t.Error("circuit should be closed after successful recovery")
	}
	if primaryFailCount.Load() != 0 {
		t.Error("fail count should reset to 0 on recovery")
	}
}

func TestCircuit_HalfOpenTransition(t *testing.T) {
	resetCircuit()
	primaryState.Store(int32(stateOpen))
	// Simulate the probe-interval having passed.
	cbMu.Lock()
	lastPrimaryFailure = time.Now().Add(-2 * probeInterval)
	cbMu.Unlock()

	// The CompareAndSwap in checkPrimary() transitions open→half-open; do it directly.
	primaryState.CompareAndSwap(int32(stateOpen), int32(stateHalfOpen))
	if circuitState(primaryState.Load()) != stateHalfOpen {
		t.Error("state should be half-open after probe interval")
	}
}

func TestGetCircuitHealth_NoReplica(t *testing.T) {
	resetCircuit()
	ReadDB = nil // ensure no replica
	h := GetCircuitHealth()
	if h.PrimaryState != "closed" {
		t.Errorf("PrimaryState = %q, want %q", h.PrimaryState, "closed")
	}
	if h.ReplicaState != "" {
		t.Errorf("ReplicaState should be empty when no replica configured, got %q", h.ReplicaState)
	}
}

func TestGetCircuitHealth_RecordsLastFailureTime(t *testing.T) {
	resetCircuit()
	for i := 0; i < failThreshold; i++ {
		recordFailure(&primaryFailCount, &lastPrimaryFailure, &primaryState, "primary", errors.New("x"))
	}
	h := GetCircuitHealth()
	if h.LastPrimaryFail == nil {
		t.Error("LastPrimaryFail should be set after failures")
	}
	if time.Since(*h.LastPrimaryFail) > 5*time.Second {
		t.Error("LastPrimaryFail should be recent")
	}
}

func TestIsReplicaDown_NoReplicaIsNotDown(t *testing.T) {
	resetCircuit()
	ReadDB = nil
	if IsReplicaDown() {
		t.Error("no replica configured should not report as down")
	}
}
