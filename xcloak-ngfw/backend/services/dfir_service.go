package services

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/lib/pq"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// defaultArtifactTypes is the standard forensic collection suite.
var defaultArtifactTypes = []string{
	"process_snapshot",    // rich: parent tree, cmdline, hashes, modules, open files
	"collect_processes",   // lightweight snapshot (lower agent overhead)
	"collect_connections",
	"collect_services",
	"collect_packages",
	"collect_users",
	"collect_auth_logs",
	"collect_file_hashes",
}

// quickArtifactTypes is a faster subset for high-urgency collections.
var quickArtifactTypes = []string{
	"process_snapshot",
	"collect_connections",
	"collect_auth_logs",
}

// TriggerForensicCollection creates a collection record and queues artifact
// collection tasks for the given agent. Returns the new collection ID.
func TriggerForensicCollection(agentID, tenantID int, incidentID *int, label, username string, artifactTypes []string) (int, error) {
	if len(artifactTypes) == 0 {
		artifactTypes = defaultArtifactTypes
	}

	var collID int
	err := database.DB.QueryRow(`
		INSERT INTO forensic_collections
		  (tenant_id, incident_id, agent_id, label, status, artifact_types, triggered_by, started_at)
		VALUES ($1,$2,$3,$4,'running',$5,$6,NOW())
		RETURNING id`,
		tenantID, incidentID, agentID, label, pq.Array(artifactTypes), username,
	).Scan(&collID)
	if err != nil {
		return 0, err
	}

	// Queue each artifact task; errors are non-fatal (best-effort)
	payload, _ := json.Marshal(map[string]any{"collection_id": collID})
	for _, taskType := range artifactTypes {
		task := models.AgentTask{
			AgentID:  agentID,
			TaskType: taskType,
			Payload:  payload,
			Status:   "pending",
		}
		if err := CreateTask(task); err != nil {
			log.Printf("[DFIR] queue task %s for agent %d: %v", taskType, agentID, err)
		}
	}

	// Background: poll task completion and finalize collection
	go monitorCollection(collID, tenantID, agentID, artifactTypes)
	return collID, nil
}

func monitorCollection(collID, tenantID, agentID int, artifactTypes []string) {
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(15 * time.Second)

		// Count completed tasks that reference this collection
		var done int
		database.DB.QueryRow(`
			SELECT COUNT(*) FROM agent_tasks
			WHERE agent_id=$1 AND status='completed'
			  AND payload::jsonb->>'collection_id' = $2::text
			  AND task_type = ANY($3)`,
			agentID, collID, pq.Array(artifactTypes),
		).Scan(&done)

		if done >= len(artifactTypes) {
			database.DB.Exec(`
				UPDATE forensic_collections SET status='completed', completed_at=NOW()
				WHERE id=$1`, collID)
			log.Printf("[DFIR] collection #%d completed (%d artifacts)", collID, done)
			return
		}
	}
	// Timeout — mark partial
	database.DB.Exec(`
		UPDATE forensic_collections SET status='partial', completed_at=NOW()
		WHERE id=$1`, collID)
}

// StoreForensicArtifact persists a task result as a forensic artifact.
// Called by the task-completion handler when payload has a collection_id.
func StoreForensicArtifact(collID, tenantID, agentID int, artifactType string, data json.RawMessage) error {
	// Count items in the JSON array
	var items []json.RawMessage
	json.Unmarshal(data, &items)

	_, err := database.DB.Exec(`
		INSERT INTO forensic_artifacts (collection_id, tenant_id, agent_id, artifact_type, data, item_count)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT DO NOTHING`,
		collID, tenantID, agentID, artifactType, data, len(items))
	return err
}

// ── Query ──────────────────────────────────────────────────────────────────

func ListForensicCollections(tenantID, limit int) ([]models.ForensicCollection, error) {
	rows, err := database.DB.Query(`
		SELECT fc.id, fc.tenant_id, fc.incident_id, fc.agent_id,
		       COALESCE(a.hostname,'') AS hostname,
		       fc.label, fc.status, fc.artifact_types, fc.triggered_by,
		       fc.started_at, fc.completed_at, fc.created_at,
		       COUNT(fa.id) AS artifact_count
		FROM forensic_collections fc
		LEFT JOIN agents a ON a.id=fc.agent_id
		LEFT JOIN forensic_artifacts fa ON fa.collection_id=fc.id
		WHERE fc.tenant_id=$1
		GROUP BY fc.id, a.hostname
		ORDER BY fc.created_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ForensicCollection
	for rows.Next() {
		var c models.ForensicCollection
		rows.Scan(&c.ID, &c.TenantID, &c.IncidentID, &c.AgentID, &c.AgentHostname,
			&c.Label, &c.Status, pq.Array(&c.ArtifactTypes),
			&c.TriggeredBy, &c.StartedAt, &c.CompletedAt, &c.CreatedAt, &c.ArtifactCount)
		out = append(out, c)
	}
	return out, nil
}

func GetCollectionArtifacts(collID, tenantID int) ([]models.ForensicArtifact, error) {
	rows, err := database.DB.Query(`
		SELECT id, collection_id, tenant_id, agent_id, artifact_type, data, item_count, collected_at
		FROM forensic_artifacts WHERE collection_id=$1 AND tenant_id=$2
		ORDER BY collected_at`, collID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ForensicArtifact
	for rows.Next() {
		var a models.ForensicArtifact
		rows.Scan(&a.ID, &a.CollectionID, &a.TenantID, &a.AgentID,
			&a.ArtifactType, &a.Data, &a.ItemCount, &a.CollectedAt)
		out = append(out, a)
	}
	return out, nil
}

// BuildForensicTimeline merges alerts + logs + network connections for the
// time window around an incident into a unified chronological event list.
func BuildForensicTimeline(incidentID, tenantID int) ([]models.ForensicTimelineEvent, error) {
	// Get incident time window
	var start, end time.Time
	err := database.DB.QueryRow(`
		SELECT created_at, COALESCE(resolved_at, NOW()) FROM incidents
		WHERE id=$1 AND tenant_id=$2`, incidentID, tenantID,
	).Scan(&start, &end)
	if err != nil {
		return nil, fmt.Errorf("incident not found")
	}
	// Expand window ±1h to capture context
	windowStart := start.Add(-1 * time.Hour)
	windowEnd := end.Add(1 * time.Hour)

	var events []models.ForensicTimelineEvent

	// Alerts
	rows, _ := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, a.created_at,
		       COALESCE(ag.hostname,'') AS hostname, COALESCE(a.agent_id,0)
		FROM alerts a LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE a.tenant_id=$1 AND a.created_at BETWEEN $2 AND $3
		ORDER BY a.created_at LIMIT 200`, tenantID, windowStart, windowEnd)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var e models.ForensicTimelineEvent
			var ruleName string
			e.Source = "alert"
			rows.Scan(&e.RawID, &ruleName, &e.Severity, &e.Time, &e.Hostname, &e.AgentID)
			e.EventType = "alert"
			e.Summary = ruleName
			events = append(events, e)
		}
	}

	// Logs
	rows2, _ := database.DB.Query(`
		SELECT id, log_source, log_message, collected_at, COALESCE(agent_id,0)
		FROM logs WHERE tenant_id=$1 AND collected_at BETWEEN $2 AND $3
		ORDER BY collected_at LIMIT 300`, tenantID, windowStart, windowEnd)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var e models.ForensicTimelineEvent
			var src, msg string
			e.Source = "log"
			rows2.Scan(&e.RawID, &src, &msg, &e.Time, &e.AgentID)
			e.EventType = src
			if len(msg) > 120 {
				msg = msg[:120] + "…"
			}
			e.Summary = msg
			events = append(events, e)
		}
	}

	// Network connections
	rows3, _ := database.DB.Query(`
		SELECT ec.id, COALESCE(ag.hostname,''), ec.dst_ip, ec.dst_port, ec.event_ts, ec.agent_id
		FROM endpoint_connections ec
		LEFT JOIN agents ag ON ag.id=ec.agent_id
		WHERE ec.tenant_id=$1 AND ec.event_ts BETWEEN $2 AND $3
		ORDER BY ec.event_ts LIMIT 200`, tenantID, windowStart, windowEnd)
	if rows3 != nil {
		defer rows3.Close()
		for rows3.Next() {
			var e models.ForensicTimelineEvent
			var dst string
			var port int
			e.Source = "connection"
			e.EventType = "network"
			rows3.Scan(&e.RawID, &e.Hostname, &dst, &port, &e.Time, &e.AgentID)
			e.Summary = fmt.Sprintf("Connection → %s:%d", dst, port)
			events = append(events, e)
		}
	}

	// Sort all by time
	sort.Slice(events, func(i, j int) bool {
		return events[i].Time.Before(events[j].Time)
	})
	return events, nil
}
