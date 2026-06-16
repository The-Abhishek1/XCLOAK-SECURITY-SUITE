package services

import (
	"sync"
	"time"
)

// tokenBlacklist stores revoked JWTs until their natural expiry.
// Uses in-memory map with periodic cleanup.
// For multi-instance deployments, replace with Redis.
type tokenBlacklist struct {
	mu     sync.RWMutex
	tokens map[string]time.Time // token → expiry
}

var blacklist = &tokenBlacklist{
	tokens: make(map[string]time.Time),
}

func init() {
	// Cleanup expired entries every 10 minutes.
	go func() {
		for {
			time.Sleep(10 * time.Minute)
			blacklist.cleanup()
		}
	}()
}

// RevokeToken adds a token to the blacklist until its expiry time.
func RevokeToken(token string, expiry time.Time) {
	blacklist.mu.Lock()
	defer blacklist.mu.Unlock()
	blacklist.tokens[token] = expiry
}

// IsRevoked returns true if the token has been blacklisted.
func IsRevoked(token string) bool {
	blacklist.mu.RLock()
	defer blacklist.mu.RUnlock()
	exp, ok := blacklist.tokens[token]
	if !ok {
		return false
	}
	// If the token has naturally expired, it's not relevant anymore.
	if time.Now().After(exp) {
		return false
	}
	return true
}

func (b *tokenBlacklist) cleanup() {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	for token, exp := range b.tokens {
		if now.After(exp) {
			delete(b.tokens, token)
		}
	}
}
