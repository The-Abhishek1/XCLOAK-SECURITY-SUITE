package services

import (
	"sync"
	"time"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// sigmaCacheTTL is a safety net in case some mutation path forgets to call
// InvalidateSigmaCache — worst case, a rule change takes this long to take
// effect on log evaluation instead of immediately.
const sigmaCacheTTL = 30 * time.Second

type sigmaCacheEntry struct {
	rules     []models.SigmaRule
	expiresAt time.Time
}

var (
	sigmaCacheMu sync.RWMutex
	sigmaCache   = map[int]sigmaCacheEntry{} // tenantID -> entry
)

// getEnabledSigmaRulesCached returns tenantID's enabled Sigma rules, querying
// the DB only on a cache miss/expiry. EvaluateRules previously called
// GetEnabledRulesForAgent on every single ingested log line — one DB
// round-trip per log — which this removes from the hot path.
func getEnabledSigmaRulesCached(tenantID int) ([]models.SigmaRule, error) {
	sigmaCacheMu.RLock()
	entry, ok := sigmaCache[tenantID]
	sigmaCacheMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return entry.rules, nil
	}

	rules, err := repositories.GetEnabledRules(tenantID)
	if err != nil {
		return nil, err
	}

	sigmaCacheMu.Lock()
	sigmaCache[tenantID] = sigmaCacheEntry{rules: rules, expiresAt: time.Now().Add(sigmaCacheTTL)}
	sigmaCacheMu.Unlock()

	return rules, nil
}

// InvalidateSigmaCache drops tenantID's cached rule set so the next
// evaluation re-fetches from the DB — called after any create/update/
// delete/enable/disable/import so a rule change takes effect immediately
// rather than waiting out sigmaCacheTTL.
func InvalidateSigmaCache(tenantID int) {
	sigmaCacheMu.Lock()
	delete(sigmaCache, tenantID)
	sigmaCacheMu.Unlock()
}
