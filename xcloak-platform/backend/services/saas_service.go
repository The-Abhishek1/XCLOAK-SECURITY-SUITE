package services

import (
	"os"
	"sync/atomic"
	"time"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// saasEnabled is the in-process cache of the SAAS_MODE flag.
// 0 = off, 1 = on. Toggled by SetSaasMode.
var saasEnabled atomic.Int32

// InitSaasMode loads the effective SAAS_MODE on startup:
// env var takes precedence; DB setting is the fallback so the UI toggle works
// without a restart.
func InitSaasMode() {
	env := os.Getenv("SAAS_MODE")
	if env == "true" {
		saasEnabled.Store(1)
		return
	}
	if env == "false" {
		saasEnabled.Store(0)
		return
	}
	// No env var set — use DB value (what the UI toggle writes).
	if repositories.GetSystemConfig("saas_mode") == "true" {
		saasEnabled.Store(1)
	}
}

// SaasModeEnabled reports whether SaaS enforcement is active.
func SaasModeEnabled() bool {
	return saasEnabled.Load() == 1
}

// SetSaasMode updates the in-process flag and persists it to the DB so it
// survives restarts (when the env var is not set).
func SetSaasMode(on bool) error {
	val := "false"
	if on {
		val = "true"
		saasEnabled.Store(1)
	} else {
		saasEnabled.Store(0)
	}
	return repositories.SetSystemConfig("saas_mode", val)
}

// GetSubscription returns the tenant's active subscription, creating a trial
// one if none exists yet.
func GetSubscription(tenantID int) (models.Subscription, error) {
	sub, err := repositories.GetSubscriptionByTenant(tenantID)
	if err == repositories.ErrSubscriptionNotFound {
		_ = repositories.EnsureSubscription(tenantID)
		sub, err = repositories.GetSubscriptionByTenant(tenantID)
	}
	return sub, err
}

// GetAllSubscriptions returns every tenant's subscription (platform admin use).
func GetAllSubscriptions() ([]models.Subscription, error) {
	return repositories.GetAllSubscriptions()
}

// GetAllPlans returns all available plans.
func GetAllPlans() ([]models.Plan, error) {
	return repositories.GetAllPlans()
}

// UpdateSubscription changes a tenant's plan and status.
func UpdateSubscription(tenantID int, planName, status string, notes *string) error {
	return repositories.UpdateSubscription(tenantID, repositories.SubUpdate{
		PlanName: planName,
		Status:   status,
		Notes:    notes,
	})
}

// TenantUsage holds live usage numbers for a tenant.
type TenantUsage struct {
	AgentCount int `json:"agent_count"`
	UserCount  int `json:"user_count"`
	IOCCount   int `json:"ioc_count"`
}

func GetTenantUsage(tenantID int) TenantUsage {
	var u TenantUsage
	database.DB.QueryRow(`SELECT COUNT(*) FROM agents  WHERE tenant_id = $1`, tenantID).Scan(&u.AgentCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM users   WHERE tenant_id = $1`, tenantID).Scan(&u.UserCount)
	database.DB.QueryRow(`SELECT COUNT(*) FROM iocs    WHERE tenant_id = $1 AND enabled = true`, tenantID).Scan(&u.IOCCount)
	return u
}

// SaasStats is returned to the platform admin dashboard.
type SaasStats struct {
	TotalTenants    int     `json:"total_tenants"`
	ActiveTenants   int     `json:"active_tenants"`
	TrialTenants    int     `json:"trial_tenants"`
	SuspendedTenants int    `json:"suspended_tenants"`
	MRR             float64 `json:"mrr"`
}

func GetSaasStats() (SaasStats, error) {
	subs, err := repositories.GetAllSubscriptions()
	if err != nil {
		return SaasStats{}, err
	}
	var stats SaasStats
	stats.TotalTenants = len(subs)
	for _, s := range subs {
		switch s.Status {
		case "active":
			stats.ActiveTenants++
			stats.MRR += s.PriceMonthly
		case "trial":
			stats.TrialTenants++
		case "suspended", "cancelled":
			stats.SuspendedTenants++
		}
	}
	return stats, nil
}

// CheckAgentLimit returns true when the tenant can enroll another agent.
// When SaaS mode is off this is always true.
func CheckAgentLimit(tenantID int) bool {
	if !SaasModeEnabled() {
		return true
	}
	sub, err := GetSubscription(tenantID)
	if err != nil || sub.Status == "suspended" || sub.Status == "cancelled" {
		return false
	}
	if sub.MaxAgents == -1 {
		return true
	}
	if sub.Status == "trial" && sub.TrialEndsAt != nil && sub.TrialEndsAt.Before(time.Now()) {
		return false
	}
	usage := GetTenantUsage(tenantID)
	return usage.AgentCount < sub.MaxAgents
}

// CheckTenantAccess returns true when the tenant is allowed to use the platform.
// A suspended or cancelled subscription blocks access. Expired trials block access.
func CheckTenantAccess(tenantID int) bool {
	if !SaasModeEnabled() {
		return true
	}
	sub, err := GetSubscription(tenantID)
	if err != nil {
		return true // fail-open when subscription row is missing
	}
	if sub.Status == "suspended" || sub.Status == "cancelled" {
		return false
	}
	if sub.Status == "trial" && sub.TrialEndsAt != nil && sub.TrialEndsAt.Before(time.Now()) {
		return false
	}
	return true
}
