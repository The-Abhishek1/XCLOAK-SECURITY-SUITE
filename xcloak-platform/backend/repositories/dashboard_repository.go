package repositories

import (
	"xcloak-platform/database"
	"xcloak-platform/models"
)

func GetDashboardOverview(tenantID int) (*models.DashboardOverview, error) {
	var o models.DashboardOverview

	err := database.DB.QueryRow(`
		WITH
		  agent_counts AS (
		    SELECT
		      COUNT(*)                                        AS total,
		      COUNT(*) FILTER (WHERE status = 'online')      AS online,
		      COUNT(*) FILTER (WHERE status = 'offline')     AS offline
		    FROM agents WHERE tenant_id = $1
		  ),
		  process_count AS (
		    SELECT COUNT(*) AS cnt FROM endpoint_processes ep
		    JOIN agents a ON a.id = ep.agent_id WHERE a.tenant_id = $1
		  ),
		  connection_count AS (
		    SELECT COUNT(*) AS cnt FROM endpoint_connections ec
		    JOIN agents a ON a.id = ec.agent_id WHERE a.tenant_id = $1
		  ),
		  service_count AS (
		    SELECT COUNT(*) AS cnt FROM endpoint_services es
		    JOIN agents a ON a.id = es.agent_id WHERE a.tenant_id = $1
		  ),
		  package_count AS (
		    SELECT COUNT(*) AS cnt FROM endpoint_packages ep
		    JOIN agents a ON a.id = ep.agent_id WHERE a.tenant_id = $1
		  ),
		  user_count AS (
		    SELECT COUNT(*) AS cnt FROM endpoint_users eu
		    JOIN agents a ON a.id = eu.agent_id WHERE a.tenant_id = $1
		  ),
		  alert_counts AS (
		    SELECT
		      COUNT(*)                                                              AS total,
		      COUNT(*) FILTER (WHERE severity = 'critical')                        AS critical,
		      COUNT(*) FILTER (WHERE status = 'open'
		                        AND (suppressed_until IS NULL OR suppressed_until < NOW())) AS open,
		      COUNT(*) FILTER (WHERE suppressed_until IS NOT NULL
		                        AND suppressed_until >= NOW())                      AS snoozed
		    FROM alerts WHERE tenant_id = $1
		  ),
		  incident_counts AS (
		    SELECT
		      COUNT(*)                                       AS total,
		      COUNT(*) FILTER (WHERE severity = 'critical') AS critical
		    FROM incidents WHERE tenant_id = $1
		  )
		SELECT
		  a.total, a.online, a.offline,
		  p.cnt, c.cnt, s.cnt, pkg.cnt, u.cnt,
		  al.total, al.critical, al.open, al.snoozed,
		  i.total, i.critical
		FROM agent_counts a, process_count p, connection_count c,
		     service_count s, package_count pkg, user_count u,
		     alert_counts al, incident_counts i
	`, tenantID).Scan(
		&o.Agents, &o.OnlineAgents, &o.OfflineAgents,
		&o.Processes, &o.Connections, &o.Services, &o.Packages, &o.Users,
		&o.Alerts, &o.CriticalAlerts, &o.OpenAlerts, &o.SnoozedAlerts,
		&o.Incidents, &o.CriticalIncidents,
	)
	if err != nil {
		return nil, err
	}
	return &o, nil
}
