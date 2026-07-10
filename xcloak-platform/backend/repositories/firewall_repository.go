package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

const firewallCols = `id, name, description, group_name,
       source_ip, destination_ip, protocol, port,
       action, enabled, COALESCE(priority, 100), hit_count, synced_at`

func scanRule(dest *models.FirewallRule, scanner interface {
	Scan(...interface{}) error
}) error {
	return scanner.Scan(
		&dest.ID, &dest.Name, &dest.Description, &dest.GroupName,
		&dest.SourceIP, &dest.DestinationIP, &dest.Protocol, &dest.Port,
		&dest.Action, &dest.Enabled, &dest.Priority, &dest.HitCount, &dest.SyncedAt,
	)
}

func CreateRule(rule models.FirewallRule, tenantID int) error {
	if rule.Priority == 0 {
		rule.Priority = 100
	}
	if rule.GroupName == "" {
		rule.GroupName = "default"
	}
	_, err := database.DB.Exec(`
		INSERT INTO firewall_rules
		(name, description, group_name, source_ip, destination_ip,
		 protocol, port, action, enabled, priority, tenant_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
	`,
		rule.Name, rule.Description, rule.GroupName,
		rule.SourceIP, rule.DestinationIP,
		rule.Protocol, rule.Port, rule.Action,
		rule.Enabled, rule.Priority, tenantID,
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
	err := database.DB.QueryRow(
		`SELECT `+firewallCols+` FROM firewall_rules WHERE id=$1 AND tenant_id=$2`,
		id, tenantID,
	).Scan(
		&r.ID, &r.Name, &r.Description, &r.GroupName,
		&r.SourceIP, &r.DestinationIP, &r.Protocol, &r.Port,
		&r.Action, &r.Enabled, &r.Priority, &r.HitCount, &r.SyncedAt,
	)
	if err != nil {
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
	result, err := database.DB.Exec(`
		UPDATE firewall_rules
		SET name=$1, description=$2, group_name=$3,
		    source_ip=$4, destination_ip=$5,
		    protocol=$6, port=$7, action=$8,
		    enabled=$9, priority=$10
		WHERE id=$11 AND tenant_id=$12
	`,
		rule.Name, rule.Description, rule.GroupName,
		rule.SourceIP, rule.DestinationIP,
		rule.Protocol, rule.Port, rule.Action,
		rule.Enabled, rule.Priority, id, tenantID,
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
// hit_count on firewall_rules. Only updates rules that belong to tenantID's
// agents (via the agent_id → tenant_id join) — prevents cross-tenant poisoning.
func RecordFirewallHits(agentID, tenantID int, hits []FirewallHit) error {
	for _, h := range hits {
		// Verify the rule belongs to this tenant before updating.
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

		// Update cumulative counter (add the delta).
		database.DB.Exec(`
			UPDATE firewall_rules SET hit_count = hit_count + $1 WHERE id=$2 AND tenant_id=$3
		`, h.Hits, h.RuleID, tenantID)
	}
	return nil
}

// GetFirewallStats returns aggregated analytics for the tenant's rules.
func GetFirewallStats(tenantID int) (map[string]interface{}, error) {
	stats := map[string]interface{}{}

	// Top 10 rules by hit_count.
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

	// Total hits last 24h from the hits table.
	var totalHits int64
	database.DB.QueryRow(`
		SELECT COALESCE(SUM(hits),0) FROM firewall_rule_hits
		WHERE tenant_id=$1 AND reported_at > NOW() - INTERVAL '24 hours'
	`, tenantID).Scan(&totalHits)
	stats["total_hits_24h"] = totalHits

	// Per-agent hit totals (24h).
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
	var rules []models.FirewallRule
	for rows.Next() {
		var r models.FirewallRule
		if err := rows.Scan(
			&r.ID, &r.Name, &r.Description, &r.GroupName,
			&r.SourceIP, &r.DestinationIP, &r.Protocol, &r.Port,
			&r.Action, &r.Enabled, &r.Priority, &r.HitCount, &r.SyncedAt,
		); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, nil
}
