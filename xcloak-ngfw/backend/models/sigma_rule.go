package models

import "time"

type SigmaRule struct {
	ID int `json:"id"`

	Title string `json:"title"`

	Severity string `json:"severity"`

	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	MitreName      string `json:"mitre_name"`

	// Legacy: flat keyword list. Kept for backward compatibility — if
	// Selections is empty, the engine treats Keywords as a single
	// selection named "selection1" with Condition "selection1".
	Keywords []string `json:"keywords"`

	// Sigma-lite: named groups of keywords. A selection is TRUE if ANY
	// keyword in its list is found in the log message (case-insensitive).
	// Example: {"selection1": ["sudo","session opened"], "selection2": ["root"]}
	Selections map[string][]string `json:"selections"`

	// Boolean expression over selection names, e.g.
	//   "selection1 and selection2"
	//   "selection1 or selection2"
	//   "selection1 and not selection2"
	//   "(selection1 or selection2) and selection3"
	// Supports: and, or, not, parentheses. Empty = OR of all selections
	// (backward-compatible "any keyword anywhere" behavior).
	Condition string `json:"condition"`

	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
}
