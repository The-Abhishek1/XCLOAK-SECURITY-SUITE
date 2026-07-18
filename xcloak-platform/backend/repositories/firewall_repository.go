package repositories

import (
	"time"

	"github.com/lib/pq"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

const firewallCols = `id, name, description, group_name,
       source_ip, destination_ip, protocol, port,
       COALESCE(port_range,''), COALESCE(direction,'both'),
       COALESCE(log_enabled,false), COALESCE(log_prefix,''),
       action, enabled, COALESCE(priority, 100), hit_count,
       COALESCE(tags,'{}'), expires_at,
       COALESCE(created_by,'system'), COALESCE(updated_by,'system'),
       COALESCE(updated_at,NOW()), synced_at`

func scanRule(dest *models.FirewallRule, scanner interface {
	Scan(...interface{}) error
}) error {
	var tags pq.StringArray
	err := scanner.Scan(
		&dest.ID, &dest.Name, &dest.Description, &dest.GroupName,
		&dest.SourceIP, &dest.DestinationIP, &dest.Protocol, &dest.Port,
		&dest.PortRange, &dest.Direction,
		&dest.LogEnabled, &dest.LogPrefix,
		&dest.Action, &dest.Enabled, &dest.Priority, &dest.HitCount,
		&tags, &dest.ExpiresAt,
		&dest.CreatedBy, &dest.UpdatedBy, &dest.UpdatedAt,
		&dest.SyncedAt,
	)
	if err == nil {
		dest.Tags = []string(tags)
	}
	return err
}

func CreateRule(rule models.FirewallRule, tenantID int) error {
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	if rule.GroupName == "" {
		rule.GroupName = "default"
	}
	if rule.Direction == "" {
		rule.Direction = "both"
	}
	if rule.CreatedBy == "" {
		rule.CreatedBy = "system"
	}
	tags := pq.StringArray(rule.Tags)
	_, err := database.DB.Exec(`
		INSERT INTO firewall_rules
		(name, description, group_name, source_ip, destination_ip,
		 protocol, port, port_range, direction, log_enabled, log_prefix,
		 action, enabled, priority, tags, expires_at, created_by, updated_by, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
	`,
		rule.Name, rule.Description, rule.GroupName,
		rule.SourceIP, rule.DestinationIP,
		rule.Protocol, rule.Port, rule.PortRange, rule.Direction,
		rule.LogEnabled, rule.LogPrefix,
		rule.Action, rule.Enabled, rule.Priority,
		tags, rule.ExpiresAt, rule.CreatedBy, rule.CreatedBy,
		tenantID,
	)
	return err
}

func GetRulesForTenant(tenantID int) ([]models.FirewallRule, error) {
	return queryRules(`WHERE tenant_id = $1 ORDER BY COALESCE(priority, 100), id`, tenantID)
}

func GetRulesForGroup(group string, tenantID int) ([]models.FirewallRule, error) {
	return queryRules(`WHERE tenant_id = $1 AND group_name = $2 ORDER BY COALESCE(priority,100), id`, tenantID, group)
}

func GetRuleByID(id string, tenantID int) (*models.FirewallRule, error) {
	var r models.FirewallRule
	row := database.DB.QueryRow(
		`SELECT `+firewallCols+` FROM firewall_rules WHERE id=$1 AND tenant_id=$2`,
		id, tenantID,
	)
	if err := scanRule(&r, row); err != nil {
		return nil, err
	}
	return &r, nil
}

func UpdateRule(id string, rule models.FirewallRule, tenantID int) (int64, error) {
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	if rule.GroupName == "" {
		rule.GroupName = "default"
	}
	if rule.Direction == "" {
		rule.Direction = "both"
	}
	if rule.UpdatedBy == "" {
		rule.UpdatedBy = "system"
	}
	tags := pq.StringArray(rule.Tags)
	result, err := database.DB.Exec(`
		UPDATE firewall_rules
		SET name=$1, description=$2, group_name=$3,
		    source_ip=$4, destination_ip=$5,
		    protocol=$6, port=$7, port_range=$8,
		    direction=$9, log_enabled=$10, log_prefix=$11,
		    action=$12, enabled=$13, priority=$14,
		    tags=$15, expires_at=$16, updated_by=$17, updated_at=NOW()
		WHERE id=$18 AND tenant_id=$19
	`,
		rule.Name, rule.Description, rule.GroupName,
		rule.SourceIP, rule.DestinationIP,
		rule.Protocol, rule.Port, rule.PortRange,
		rule.Direction, rule.LogEnabled, rule.LogPrefix,
		rule.Action, rule.Enabled, rule.Priority,
		tags, rule.ExpiresAt, rule.UpdatedBy,
		id, tenantID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func DeleteRule(id string, tenantID int) (int64, error) {
	result, err := database.DB.Exec(
		`DELETE FROM firewall_rules WHERE id=$1 AND tenant_id=$2`, id, tenantID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// BulkAction performs enable/disable/delete on a list of rule IDs for a tenant.
// Returns the number of rows affected.
func BulkAction(ids []int, action string, tenantID int) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	pqIDs := pq.Array(ids)
	var result interface {
		RowsAffected() (int64, error)
	}
	var err error
	switch action {
	case "enable":
		result, err = database.DB.Exec(
			`UPDATE firewall_rules SET enabled=true, updated_at=NOW() WHERE id=ANY($1) AND tenant_id=$2`,
			pqIDs, tenantID,
		)
	case "disable":
		result, err = database.DB.Exec(
			`UPDATE firewall_rules SET enabled=false, updated_at=NOW() WHERE id=ANY($1) AND tenant_id=$2`,
			pqIDs, tenantID,
		)
	case "delete":
		result, err = database.DB.Exec(
			`DELETE FROM firewall_rules WHERE id=ANY($1) AND tenant_id=$2`,
			pqIDs, tenantID,
		)
	default:
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// PruneExpiredRules deletes rules whose expires_at is in the past for the tenant.
func PruneExpiredRules(tenantID int) (int64, error) {
	result, err := database.DB.Exec(
		`DELETE FROM firewall_rules WHERE tenant_id=$1 AND expires_at IS NOT NULL AND expires_at < NOW()`,
		tenantID,
	)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

// GetExpiredRules lists rules that have expired but not yet been pruned.
func GetExpiredRules(tenantID int) ([]models.FirewallRule, error) {
	return queryRules(
		`WHERE tenant_id=$1 AND expires_at IS NOT NULL AND expires_at < NOW() ORDER BY expires_at`,
		tenantID,
	)
}

// GetFirewallPolicy returns the default action for a tenant ("allow" or "deny").
func GetFirewallPolicy(tenantID int) (string, error) {
	var action string
	err := database.DB.QueryRow(
		`SELECT default_action FROM firewall_policy WHERE tenant_id=$1`, tenantID,
	).Scan(&action)
	if err != nil {
		return "allow", nil // default when no row exists
	}
	return action, nil
}

// SetFirewallPolicy upserts the default action for a tenant.
func SetFirewallPolicy(tenantID int, defaultAction, updatedBy string) error {
	_, err := database.DB.Exec(`
		INSERT INTO firewall_policy (tenant_id, default_action, updated_by, updated_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (tenant_id) DO UPDATE
		    SET default_action=$2, updated_by=$3, updated_at=NOW()
	`, tenantID, defaultAction, updatedBy)
	return err
}

// GetFirewallGroups returns distinct groups with rule/enabled counts.
func GetFirewallGroups(tenantID int) ([]map[string]interface{}, error) {
	rows, err := database.DB.Query(`
		SELECT group_name,
		       COUNT(*)              AS total_rules,
		       COUNT(*) FILTER (WHERE enabled) AS enabled_rules,
		       COALESCE(SUM(hit_count), 0)   AS total_hits
		FROM firewall_rules WHERE tenant_id=$1
		GROUP BY group_name ORDER BY group_name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []map[string]interface{}
	for rows.Next() {
		var name string
		var total, enabled int
		var hits int64
		if rows.Scan(&name, &total, &enabled, &hits) == nil {
			groups = append(groups, map[string]interface{}{
				"name": name, "total_rules": total,
				"enabled_rules": enabled, "total_hits": hits,
			})
		}
	}
	return groups, nil
}

// FirewallHit is a per-rule packet count submitted by an agent.
type FirewallHit struct {
	RuleID int   `json:"rule_id"`
	Hits   int64 `json:"hits"`
}

// RecordFirewallHits inserts per-rule hit reports and bumps the cumulative
// hit_count on firewall_rules.
func RecordFirewallHits(agentID, tenantID int, hits []FirewallHit) error {
	for _, h := range hits {
		var rTenant int
		err := database.DB.QueryRow(
			`SELECT tenant_id FROM firewall_rules WHERE id=$1`, h.RuleID,
		).Scan(&rTenant)
		if err != nil || rTenant != tenantID {
			continue
		}

		database.DB.Exec(`
			INSERT INTO firewall_rule_hits (rule_id, agent_id, tenant_id, hits, reported_at)
			VALUES ($1,$2,$3,$4,NOW())
		`, h.RuleID, agentID, tenantID, h.Hits)

		database.DB.Exec(`
			UPDATE firewall_rules SET hit_count = hit_count + $1 WHERE id=$2 AND tenant_id=$3
		`, h.Hits, h.RuleID, tenantID)
	}
	return nil
}

// GetFirewallStats returns aggregated analytics for the tenant's rules.
func GetFirewallStats(tenantID int) (map[string]interface{}, error) {
	stats := map[string]interface{}{}

	rows, err := database.DB.Query(`
		SELECT id, name, group_name, action, hit_count
		FROM firewall_rules WHERE tenant_id=$1
		ORDER BY hit_count DESC LIMIT 10
	`, tenantID)
	if err != nil {
		return nil, err
	}
	var topRules []map[string]interface{}
	for rows.Next() {
		var id int
		var name, group, action string
		var hits int64
		if rows.Scan(&id, &name, &group, &action, &hits) == nil {
			topRules = append(topRules, map[string]interface{}{
				"id": id, "name": name, "group_name": group,
				"action": action, "hit_count": hits,
			})
		}
	}
	rows.Close()
	stats["top_rules"] = topRules

	var totalHits int64
	database.DB.QueryRow(`
		SELECT COALESCE(SUM(hits),0) FROM firewall_rule_hits
		WHERE tenant_id=$1 AND reported_at > NOW() - INTERVAL '24 hours'
	`, tenantID).Scan(&totalHits)
	stats["total_hits_24h"] = totalHits

	rows2, err := database.DB.Query(`
		SELECT h.agent_id, a.hostname, COALESCE(SUM(h.hits),0)
		FROM firewall_rule_hits h
		JOIN agents a ON a.id = h.agent_id
		WHERE h.tenant_id=$1 AND h.reported_at > NOW() - INTERVAL '24 hours'
		GROUP BY h.agent_id, a.hostname ORDER BY 3 DESC LIMIT 10
	`, tenantID)
	if err == nil {
		var perAgent []map[string]interface{}
		for rows2.Next() {
			var agentID int
			var hostname string
			var hits int64
			if rows2.Scan(&agentID, &hostname, &hits) == nil {
				perAgent = append(perAgent, map[string]interface{}{
					"agent_id": agentID, "hostname": hostname, "hits": hits,
				})
			}
		}
		rows2.Close()
		stats["per_agent"] = perAgent
	}

	// Tag distribution
	tagRows, err := database.DB.Query(`
		SELECT unnest(tags) AS tag, COUNT(*) FROM firewall_rules
		WHERE tenant_id=$1 GROUP BY tag ORDER BY 2 DESC LIMIT 20
	`, tenantID)
	if err == nil {
		var tagDist []map[string]interface{}
		for tagRows.Next() {
			var tag string
			var cnt int
			if tagRows.Scan(&tag, &cnt) == nil {
				tagDist = append(tagDist, map[string]interface{}{"tag": tag, "count": cnt})
			}
		}
		tagRows.Close()
		stats["tag_distribution"] = tagDist
	}

	// Expiring soon (next 7 days)
	var expiringSoon int
	database.DB.QueryRow(`
		SELECT COUNT(*) FROM firewall_rules
		WHERE tenant_id=$1 AND expires_at IS NOT NULL
		  AND expires_at > NOW() AND expires_at < NOW() + INTERVAL '7 days'
	`, tenantID).Scan(&expiringSoon)
	stats["expiring_soon"] = expiringSoon

	return stats, nil
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

func queryRules(where string, args ...interface{}) ([]models.FirewallRule, error) {
	rows, err := database.DB.Query(
		`SELECT `+firewallCols+` FROM firewall_rules `+where, args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanRules(rows)
}

func scanRules(rows interface {
	Next() bool
	Scan(...interface{}) error
	Close() error
}) ([]models.FirewallRule, error) {
	defer rows.Close()
	rules := []models.FirewallRule{}
	for rows.Next() {
		var r models.FirewallRule
		var tags pq.StringArray
		err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.GroupName,
			&r.SourceIP, &r.DestinationIP, &r.Protocol, &r.Port,
			&r.PortRange, &r.Direction,
			&r.LogEnabled, &r.LogPrefix,
			&r.Action, &r.Enabled, &r.Priority, &r.HitCount,
			&tags, &r.ExpiresAt,
			&r.CreatedBy, &r.UpdatedBy, &r.UpdatedAt,
			&r.SyncedAt,
		)
		if err == nil {
			r.Tags = []string(tags)
			rules = append(rules, r)
		}
	}
	return rules, nil
}

// StartExpiredRuleReaper runs a background goroutine that prunes expired
// firewall rules globally every hour.
func StartExpiredRuleReaper() {
	go func() {
		t := time.NewTicker(1 * time.Hour)
		defer t.Stop()
		for range t.C {
			database.DB.Exec(
				`DELETE FROM firewall_rules WHERE expires_at IS NOT NULL AND expires_at < NOW()`,
			)
		}
	}()
}
