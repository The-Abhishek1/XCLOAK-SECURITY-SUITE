package models

import "time"

type CVECache struct {
	CVEID       string     `json:"cve_id"`
	CVSSScore   float64    `json:"cvss_score"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	PublishedAt *time.Time `json:"published_at"`
	FetchedAt   time.Time  `json:"fetched_at"`
}
