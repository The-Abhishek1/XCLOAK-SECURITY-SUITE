package services

import (
	"sync"
	"time"
)

// ttlMap is a concurrent-safe deduplication set with per-key TTL.
// Detectors use it to suppress re-alerting on the same pattern within
// a cooldown window without hitting the database.
type ttlMap struct {
	mu  sync.Mutex
	m   map[string]time.Time
	ttl time.Duration
}

func newTTLMap(ttl time.Duration) *ttlMap {
	t := &ttlMap{m: make(map[string]time.Time), ttl: ttl}
	go t.gc()
	return t
}

// touched returns true if key was seen within the TTL window.
func (t *ttlMap) touched(key string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	exp, ok := t.m[key]
	return ok && time.Now().Before(exp)
}

// touch marks key as seen now, resetting its TTL.
func (t *ttlMap) touch(key string) {
	t.mu.Lock()
	t.m[key] = time.Now().Add(t.ttl)
	t.mu.Unlock()
}

// gc removes expired entries every TTL/2 interval.
func (t *ttlMap) gc() {
	tick := time.NewTicker(t.ttl / 2)
	defer tick.Stop()
	for range tick.C {
		now := time.Now()
		t.mu.Lock()
		for k, exp := range t.m {
			if now.After(exp) {
				delete(t.m, k)
			}
		}
		t.mu.Unlock()
	}
}
