package models

import "time"

type AssetRiskScore struct {
	ID int `json:"id"`

	AgentID int `json:"agent_id"`

	RiskScore int `json:"risk_score"`

	RiskLevel string `json:"risk_level"`

	UpdatedAt time.Time `json:"updated_at"`
}
