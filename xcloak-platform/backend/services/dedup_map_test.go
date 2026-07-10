package services

import (
	"testing"
	"time"
)

func TestTTLMap_NotTouchedInitially(t *testing.T) {
	m := newTTLMap(100 * time.Millisecond)
	if m.touched("key1") {
		t.Error("key1 should not be seen before touch")
	}
}

func TestTTLMap_TouchedAfterTouch(t *testing.T) {
	m := newTTLMap(time.Second)
	m.touch("key1")
	if !m.touched("key1") {
		t.Error("key1 should be seen after touch")
	}
}

func TestTTLMap_ExpiredAfterTTL(t *testing.T) {
	m := newTTLMap(50 * time.Millisecond)
	m.touch("key1")
	time.Sleep(60 * time.Millisecond)
	if m.touched("key1") {
		t.Error("key1 should have expired")
	}
}

func TestTTLMap_MultipleKeys(t *testing.T) {
	m := newTTLMap(time.Second)
	m.touch("a")
	m.touch("b")
	if !m.touched("a") || !m.touched("b") {
		t.Error("both keys should be seen")
	}
	if m.touched("c") {
		t.Error("c was never touched")
	}
}

func TestTTLMap_TouchResetsExpiry(t *testing.T) {
	m := newTTLMap(80 * time.Millisecond)
	m.touch("key")
	time.Sleep(50 * time.Millisecond)
	m.touch("key") // reset TTL
	time.Sleep(50 * time.Millisecond)
	if !m.touched("key") {
		t.Error("key should still be alive after reset")
	}
}

func TestTTLMap_GCRunsWithoutPanic(t *testing.T) {
	// Create a map with very short TTL so GC fires quickly — just ensure it
	// doesn't panic and correctly removes expired entries.
	m := newTTLMap(30 * time.Millisecond)
	m.touch("a")
	m.touch("b")
	time.Sleep(100 * time.Millisecond) // let GC fire at least once
	// after expiry and GC, entries should be gone
	if m.touched("a") || m.touched("b") {
		t.Error("expected entries to be expired and GC'd")
	}
}
