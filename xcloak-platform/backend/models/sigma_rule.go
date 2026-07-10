package models

import "time"

type SigmaRule struct {
	ID int `json:"id"`

	Title       string `json:"title"`
	Description string `json:"description"`
	Status      string `json:"status"` // experimental | test | stable | deprecated

	Severity string `json:"severity"`

	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	MitreName      string `json:"mitre_name"`

	// Logsource block from the Sigma YAML
	LogsourceCategory string `json:"logsource_cat"`
	LogsourceProduct  string `json:"logsource_prod"`
	LogsourceService  string `json:"logsource_svc"`

	// Tags and false-positive hints from Sigma YAML
	Tags           []string `json:"tags"`
	FalsePositives []string `json:"falsepositives"`
	References     []string `json:"references"`

	// Legacy flat keyword list — kept for backward compatibility.
	// If Selections is non-empty, Keywords is ignored by the engine.
	Keywords []string `json:"keywords"`

	// Named detection groups.  Each selection is TRUE if the group's match
	// semantics are satisfied (OR by default; ALL if keywords are prefixed
	// with __ALL__).
	Selections map[string][]string `json:"selections"`

	// Boolean expression over selection names.
	Condition string `json:"condition"`

	Enabled bool `json:"enabled"`

	TenantID int `json:"tenant_id"`

	// Hit statistics — populated by GetSigmaStats, not stored directly.
	HitCount      int        `json:"hit_count,omitempty"`
	LastMatchedAt *time.Time `json:"last_matched_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
}
