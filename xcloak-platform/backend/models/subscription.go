package models

import (
	"encoding/json"
	"time"
)

type Plan struct {
	ID           int             `json:"id"`
	Name         string          `json:"name"`
	DisplayName  string          `json:"display_name"`
	PriceMonthly float64         `json:"price_monthly"`
	MaxAgents    int             `json:"max_agents"`
	MaxUsers     int             `json:"max_users"`
	Features     json.RawMessage `json:"features"`
}

type Subscription struct {
	ID                   int        `json:"id"`
	TenantID             int        `json:"tenant_id"`
	PlanID               int        `json:"plan_id"`
	PlanName             string     `json:"plan_name"`
	PlanDisplayName      string     `json:"plan_display_name"`
	PriceMonthly         float64    `json:"price_monthly"`
	MaxAgents            int        `json:"max_agents"`
	MaxUsers             int        `json:"max_users"`
	Features             json.RawMessage `json:"features"`
	Status               string     `json:"status"`
	TrialEndsAt          *time.Time `json:"trial_ends_at"`
	CurrentPeriodStart   time.Time  `json:"current_period_start"`
	CurrentPeriodEnd     *time.Time `json:"current_period_end"`
	StripeCustomerID     *string    `json:"stripe_customer_id,omitempty"`
	StripeSubscriptionID *string    `json:"stripe_subscription_id,omitempty"`
	Notes                *string    `json:"notes,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	UpdatedAt            time.Time  `json:"updated_at"`
}

// PlanFeatures is the structured form of Plan.Features JSON.
type PlanFeatures struct {
	DPI         bool `json:"dpi"`
	YARA        bool `json:"yara"`
	PDFReports  bool `json:"pdf_reports"`
	APIKeys     bool `json:"api_keys"`
	SSO         bool `json:"sso"`
	CustomRoles bool `json:"custom_roles"`
}
