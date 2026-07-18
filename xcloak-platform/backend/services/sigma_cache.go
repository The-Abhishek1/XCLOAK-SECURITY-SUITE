package services

import (
	"strings"
	"sync"
	"time"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// sigmaCacheTTL is a safety net in case some mutation path forgets to call
// InvalidateSigmaCache — worst case, a rule change takes this long to take
// effect on log evaluation instead of immediately.
const sigmaCacheTTL = 30 * time.Second

type sigmaCacheEntry struct {
	// rules is the full enabled-rule list — used when pf.Format is unknown.
	rules []models.SigmaRule
	// byProduct groups rules by their LogsourceProduct (lower-cased).
	// The "" key holds rules with no product constraint (applies to every log).
	// EvaluateRules uses this to skip rules whose product is incompatible with
	// the log's parsed format, reducing per-log work from O(all_rules) to
	// O(unconstrained + matching_product_bucket).
	byProduct map[string][]models.SigmaRule
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
	e, err := getSigmaCacheEntry(tenantID)
	if err != nil {
		return nil, err
	}
	return e.rules, nil
}

// getSigmaCacheEntry returns the full cache entry (with byProduct index).
func getSigmaCacheEntry(tenantID int) (*sigmaCacheEntry, error) {
	sigmaCacheMu.RLock()
	entry, ok := sigmaCache[tenantID]
	sigmaCacheMu.RUnlock()

	if ok && time.Now().Before(entry.expiresAt) {
		return &entry, nil
	}

	rules, err := repositories.GetEnabledRules(tenantID)
	if err != nil {
		return nil, err
	}

	newEntry := sigmaCacheEntry{
		rules:     rules,
		byProduct: buildProductIndex(rules),
		expiresAt: time.Now().Add(sigmaCacheTTL),
	}

	sigmaCacheMu.Lock()
	sigmaCache[tenantID] = newEntry
	sigmaCacheMu.Unlock()

	return &newEntry, nil
}

// buildProductIndex buckets rules by their lower-cased LogsourceProduct.
// Rules with no product constraint go into the "" bucket.
func buildProductIndex(rules []models.SigmaRule) map[string][]models.SigmaRule {
	idx := make(map[string][]models.SigmaRule)
	for _, r := range rules {
		key := strings.ToLower(r.LogsourceProduct)
		idx[key] = append(idx[key], r)
	}
	return idx
}

// getRulesForFormat returns the subset of cached rules that could possibly
// match a log with the given parsed format string. Rules whose LogsourceProduct
// is incompatible with the format are excluded, reducing per-log evaluation
// work without needing a DB query or changing rule semantics.
//
// The caller must still run the service-level check (LogsourceService vs
// pf.Process) since that depends on per-log data that can't be pre-indexed.
func getRulesForFormat(entry *sigmaCacheEntry, format string) []models.SigmaRule {
	switch strings.ToLower(format) {
	case "winevent":
		// Only windows-specific and unconstrained rules can match.
		return mergeRuleBuckets(entry.byProduct, "", "windows")
	case "syslog3164", "syslog5424":
		// Linux/Unix syslog — windows and network rules can't match.
		return mergeRuleBuckets(entry.byProduct, "", "linux", "unix")
	case "cef":
		// CEF is a network format — windows and linux/unix rules can't match.
		return mergeRuleBuckets(entry.byProduct, "", "network")
	case "raw":
		// Raw format is accepted by linux, unix, and network product rules,
		// but not windows. Include all those plus unconstrained.
		return mergeRuleBuckets(entry.byProduct, "", "linux", "unix", "network")
	default:
		// Unknown format — can't eliminate anything; evaluate all rules.
		return entry.rules
	}
}

func mergeRuleBuckets(idx map[string][]models.SigmaRule, keys ...string) []models.SigmaRule {
	out := []models.SigmaRule{}
	for _, k := range keys {
		out = append(out, idx[k]...)
	}
	return out
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
