package services

// ReloadSigmaRules forces the Sigma engine to re-fetch rules from the DB
// on the next log evaluation. Called after importing new rules via YAML upload.
// The sigma_engine.go uses a cached slice; this clears it so it reloads.
func ReloadSigmaRules() {
	// The engine fetches from DB on every EvaluateRules call via GetRules().
	// No in-memory cache to clear currently — this is a no-op placeholder
	// that ensures the import path compiles and future caching can hook here.
}
