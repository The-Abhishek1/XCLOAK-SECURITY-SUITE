package repositories

import (
	"database/sql"
	"errors"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

var ErrSubscriptionNotFound = errors.New("subscription not found")

const subSelectCols = `
	s.id, s.tenant_id, s.plan_id,
	p.name, p.display_name, p.price_monthly, p.max_agents, p.max_users, p.features,
	s.status, s.trial_ends_at, s.current_period_start, s.current_period_end,
	s.stripe_customer_id, s.stripe_subscription_id, s.notes,
	s.created_at, s.updated_at`

const subJoin = `
	FROM subscriptions s
	JOIN plans p ON p.id = s.plan_id`

func scanSub(row interface {
	Scan(dest ...any) error
}) (models.Subscription, error) {
	var sub models.Subscription
	err := row.Scan(
		&sub.ID, &sub.TenantID, &sub.PlanID,
		&sub.PlanName, &sub.PlanDisplayName, &sub.PriceMonthly,
		&sub.MaxAgents, &sub.MaxUsers, &sub.Features,
		&sub.Status, &sub.TrialEndsAt, &sub.CurrentPeriodStart,
		&sub.CurrentPeriodEnd, &sub.StripeCustomerID, &sub.StripeSubscriptionID,
		&sub.Notes, &sub.CreatedAt, &sub.UpdatedAt,
	)
	return sub, err
}

func GetSubscriptionByTenant(tenantID int) (models.Subscription, error) {
	row := database.DB.QueryRow(
		`SELECT `+subSelectCols+subJoin+` WHERE s.tenant_id = $1`, tenantID)
	sub, err := scanSub(row)
	if errors.Is(err, sql.ErrNoRows) {
		return sub, ErrSubscriptionNotFound
	}
	return sub, err
}

func GetAllSubscriptions() ([]models.Subscription, error) {
	rows, err := database.DB.Query(`SELECT ` + subSelectCols + subJoin + ` ORDER BY s.tenant_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.Subscription
	for rows.Next() {
		sub, err := scanSub(rows)
		if err != nil {
			continue
		}
		out = append(out, sub)
	}
	return out, nil
}

func GetAllPlans() ([]models.Plan, error) {
	rows, err := database.DB.Query(
		`SELECT id, name, display_name, price_monthly, max_agents, max_users, features
		 FROM plans ORDER BY price_monthly ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var plans []models.Plan
	for rows.Next() {
		var p models.Plan
		if err := rows.Scan(&p.ID, &p.Name, &p.DisplayName, &p.PriceMonthly, &p.MaxAgents, &p.MaxUsers, &p.Features); err != nil {
			continue
		}
		plans = append(plans, p)
	}
	return plans, nil
}

func EnsureSubscription(tenantID int) error {
	_, err := database.DB.Exec(`
		INSERT INTO subscriptions (tenant_id, plan_id, status, trial_ends_at)
		SELECT $1, (SELECT id FROM plans WHERE name = 'trial'), 'trial', NOW() + INTERVAL '14 days'
		WHERE NOT EXISTS (SELECT 1 FROM subscriptions WHERE tenant_id = $1)
	`, tenantID)
	return err
}

type SubUpdate struct {
	PlanName  string
	Status    string
	Notes     *string
}

func UpdateSubscription(tenantID int, u SubUpdate) error {
	tag, err := database.DB.Exec(`
		UPDATE subscriptions s
		SET plan_id  = (SELECT id FROM plans WHERE name = $1),
		    status   = $2,
		    notes    = $3,
		    updated_at = NOW()
		WHERE tenant_id = $4
	`, u.PlanName, u.Status, u.Notes, tenantID)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrSubscriptionNotFound
	}
	return nil
}

// GetSystemConfig reads a key from system_config; returns "" when missing.
func GetSystemConfig(key string) string {
	var val string
	database.DB.QueryRow(`SELECT value FROM system_config WHERE key = $1`, key).Scan(&val)
	return val
}

// SetSystemConfig upserts a key in system_config.
func SetSystemConfig(key, value string) error {
	_, err := database.DB.Exec(`
		INSERT INTO system_config (key, value) VALUES ($1, $2)
		ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value
	`, key, value)
	return err
}
