package models

import "time"

type SigmaRule struct {
	ID int `json:"id"`

	Title string `json:"title"`

	Severity string `json:"severity"`

	MitreTactic    string `json:"mitre_tactic"`
	MitreTechnique string `json:"mitre_technique"`
	MitreName      string `json:"mitre_name"`

	Keywords []string `json:"keywords"`

	Enabled bool `json:"enabled"`

	CreatedAt time.Time `json:"created_at"`
}
