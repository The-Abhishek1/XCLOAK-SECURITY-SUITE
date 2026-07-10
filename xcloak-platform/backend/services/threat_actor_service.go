package services

import (
	"log"
	"time"

	"github.com/lib/pq"

	"xcloak-platform/database"
	"xcloak-platform/models"
)

// ── Seed built-in actors ──────────────────────────────────────────────────

var builtinActors = []models.ThreatActor{
	{
		Name: "APT28 (Fancy Bear)", Aliases: []string{"Fancy Bear", "Sofacy", "Sednit"},
		OriginCountry: "Russia", Motivation: "espionage", Sophistication: "nation-state",
		Description:      "Russian GRU-linked APT targeting government, military, aerospace and media organizations worldwide.",
		TargetedSectors:  []string{"government", "military", "aerospace", "media"},
		MitreTechniques:  []string{"T1566", "T1059", "T1078", "T1110", "T1071", "T1105", "T1027"},
	},
	{
		Name: "APT29 (Cozy Bear)", Aliases: []string{"Cozy Bear", "The Dukes", "Nobelium"},
		OriginCountry: "Russia", Motivation: "espionage", Sophistication: "nation-state",
		Description:      "Russian SVR-linked APT known for SolarWinds supply-chain attack and long-term stealthy presence.",
		TargetedSectors:  []string{"government", "think-tank", "healthcare", "energy"},
		MitreTechniques:  []string{"T1195", "T1078", "T1021", "T1560", "T1055", "T1027", "T1071"},
	},
	{
		Name: "Lazarus Group", Aliases: []string{"Hidden Cobra", "ZINC", "Guardians of Peace"},
		OriginCountry: "North Korea", Motivation: "financial", Sophistication: "nation-state",
		Description:      "North Korean state-sponsored group responsible for WannaCry, Bangladesh Bank heist and crypto theft.",
		TargetedSectors:  []string{"financial", "cryptocurrency", "defense", "entertainment"},
		MitreTechniques:  []string{"T1566", "T1059", "T1486", "T1041", "T1105", "T1070"},
	},
	{
		Name: "APT41 (Double Dragon)", Aliases: []string{"Winnti", "Barium", "Wicked Panda"},
		OriginCountry: "China", Motivation: "espionage", Sophistication: "nation-state",
		Description:      "Chinese state-sponsored actor combining espionage with financially-motivated cybercrime.",
		TargetedSectors:  []string{"healthcare", "telecom", "technology", "gaming", "financial"},
		MitreTechniques:  []string{"T1190", "T1059", "T1078", "T1003", "T1071", "T1055"},
	},
	{
		Name: "FIN7", Aliases: []string{"Carbanak", "Navigator Group"},
		OriginCountry: "Unknown", Motivation: "financial", Sophistication: "high",
		Description:      "Prolific financially-motivated actor targeting point-of-sale systems in retail, hospitality and restaurants.",
		TargetedSectors:  []string{"retail", "hospitality", "financial", "restaurant"},
		MitreTechniques:  []string{"T1566", "T1059", "T1055", "T1078", "T1041", "T1486"},
	},
	{
		Name: "Sandworm", Aliases: []string{"Voodoo Bear", "TeleBots"},
		OriginCountry: "Russia", Motivation: "destructive", Sophistication: "nation-state",
		Description:      "Russian GRU unit responsible for NotPetya, Ukrainian power grid attacks, and Olympic Destroyer.",
		TargetedSectors:  []string{"energy", "government", "media", "critical-infrastructure"},
		MitreTechniques:  []string{"T1486", "T1565", "T1059", "T1078", "T1195", "T1070"},
	},
}

// SeedBuiltinActors inserts well-known threat actors for a tenant if none exist yet.
func SeedBuiltinActors(tenantID int) error {
	var count int
	database.DB.QueryRow(`SELECT COUNT(*) FROM threat_actors WHERE tenant_id=$1 AND is_builtin=true`, tenantID).Scan(&count)
	if count > 0 {
		return nil
	}
	for _, a := range builtinActors {
		database.DB.Exec(`
			INSERT INTO threat_actors
			  (tenant_id, name, aliases, origin_country, motivation, sophistication,
			   description, targeted_sectors, mitre_techniques, is_builtin)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,true)
			ON CONFLICT DO NOTHING`,
			tenantID, a.Name,
			pq.Array(a.Aliases), a.OriginCountry, a.Motivation, a.Sophistication,
			a.Description, pq.Array(a.TargetedSectors), pq.Array(a.MitreTechniques),
		)
	}
	return nil
}

// ── CRUD ──────────────────────────────────────────────────────────────────

func GetThreatActors(tenantID int) ([]models.ThreatActor, error) {
	// Ensure builtin actors exist
	SeedBuiltinActors(tenantID)

	rows, err := database.DB.Query(`
		SELECT ta.id, ta.tenant_id, ta.name, ta.aliases, ta.origin_country,
		       ta.motivation, ta.sophistication, ta.description,
		       ta.targeted_sectors, ta.mitre_techniques, ta.is_builtin,
		       ta.created_at, ta.updated_at,
		       COUNT(DISTINCT aat.alert_id) FILTER (
		           WHERE aat.tagged_at > NOW()-INTERVAL '30 days'
		       ) AS recent_alert_count
		FROM threat_actors ta
		LEFT JOIN actor_alert_tags aat ON aat.actor_id=ta.id
		WHERE ta.tenant_id=$1
		GROUP BY ta.id ORDER BY recent_alert_count DESC, ta.name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ThreatActor
	for rows.Next() {
		var a models.ThreatActor
		rows.Scan(&a.ID, &a.TenantID, &a.Name,
			pq.Array(&a.Aliases), &a.OriginCountry, &a.Motivation,
			&a.Sophistication, &a.Description,
			pq.Array(&a.TargetedSectors), pq.Array(&a.MitreTechniques),
			&a.IsBuiltin, &a.CreatedAt, &a.UpdatedAt, &a.RecentAlertCount)
		out = append(out, a)
	}
	return out, nil
}

func CreateThreatActor(a models.ThreatActor) (models.ThreatActor, error) {
	err := database.DB.QueryRow(`
		INSERT INTO threat_actors
		  (tenant_id, name, aliases, origin_country, motivation, sophistication,
		   description, targeted_sectors, mitre_techniques)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		RETURNING id, created_at, updated_at`,
		a.TenantID, a.Name,
		pq.Array(a.Aliases), a.OriginCountry, a.Motivation, a.Sophistication,
		a.Description, pq.Array(a.TargetedSectors), pq.Array(a.MitreTechniques),
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func DeleteThreatActor(id, tenantID int) error {
	_, err := database.DB.Exec(`DELETE FROM threat_actors WHERE id=$1 AND tenant_id=$2 AND is_builtin=false`, id, tenantID)
	return err
}

// ── Auto-tagging ──────────────────────────────────────────────────────────

// TagAlertWithActors inspects an alert's MITRE technique and matches it against
// known threat actor TTPs for the tenant, inserting actor_alert_tags.
func TagAlertWithActors(alertID, tenantID int, mitreTechnique string) {
	if mitreTechnique == "" {
		return
	}
	rows, err := database.DB.Query(`
		SELECT id, name FROM threat_actors
		WHERE tenant_id=$1 AND $2=ANY(mitre_techniques)`, tenantID, mitreTechnique)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var actorID int
		var actorName string
		rows.Scan(&actorID, &actorName)
		confidence := 60 // base confidence for technique match
		database.DB.Exec(`
			INSERT INTO actor_alert_tags (actor_id, alert_id, tenant_id, confidence, matched_technique)
			VALUES ($1,$2,$3,$4,$5) ON CONFLICT (actor_id, alert_id) DO NOTHING`,
			actorID, alertID, tenantID, confidence, mitreTechnique)
		log.Printf("[ThreatActor] Alert #%d tagged with %s (technique %s, conf %d%%)", alertID, actorName, mitreTechnique, confidence)
	}
}

// GetActorTagsForAlert returns actors tagged on a given alert.
func GetActorTagsForAlert(alertID, tenantID int) ([]models.ActorAlertTag, error) {
	rows, err := database.DB.Query(`
		SELECT aat.id, aat.actor_id, ta.name, aat.alert_id, aat.tenant_id,
		       aat.confidence, aat.matched_technique, aat.tagged_at
		FROM actor_alert_tags aat
		JOIN threat_actors ta ON ta.id=aat.actor_id
		WHERE aat.alert_id=$1 AND aat.tenant_id=$2
		ORDER BY aat.confidence DESC`, alertID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []models.ActorAlertTag
	for rows.Next() {
		var t models.ActorAlertTag
		rows.Scan(&t.ID, &t.ActorID, &t.ActorName, &t.AlertID, &t.TenantID,
			&t.Confidence, &t.MatchedTechnique, &t.TaggedAt)
		out = append(out, t)
	}
	return out, nil
}

// GetRecentActorAlerts returns recently tagged alerts for a given actor.
func GetRecentActorAlerts(actorID, tenantID, limit int) ([]map[string]any, error) {
	rows, err := database.DB.Query(`
		SELECT a.id, a.rule_name, a.severity, a.status,
		       COALESCE(ag.hostname,'') AS hostname, a.created_at,
		       aat.confidence, aat.matched_technique
		FROM actor_alert_tags aat
		JOIN alerts a ON a.id=aat.alert_id
		LEFT JOIN agents ag ON ag.id=a.agent_id
		WHERE aat.actor_id=$1 AND aat.tenant_id=$2
		ORDER BY a.created_at DESC LIMIT $3`, actorID, tenantID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var id, conf int
		var ruleName, severity, status, hostname, technique string
		var createdAt time.Time
		rows.Scan(&id, &ruleName, &severity, &status, &hostname, &createdAt, &conf, &technique)
		out = append(out, map[string]any{
			"id": id, "rule_name": ruleName, "severity": severity, "status": status,
			"hostname": hostname, "created_at": createdAt, "confidence": conf, "matched_technique": technique,
		})
	}
	return out, nil
}

// StartActorTaggingWorker runs in background and back-fills tags for recent untagged alerts.
func StartActorTaggingWorker() {
	go func() {
		for {
			rows, err := database.DB.Query(`
				SELECT DISTINCT a.id, a.tenant_id, a.mitre_technique
				FROM alerts a
				WHERE a.mitre_technique != '' AND a.mitre_technique IS NOT NULL
				  AND a.created_at > NOW()-INTERVAL '7 days'
				  AND NOT EXISTS (
				      SELECT 1 FROM actor_alert_tags WHERE alert_id=a.id
				  )
				LIMIT 200`)
			if err == nil {
				for rows.Next() {
					var id, tid int
					var tech string
					rows.Scan(&id, &tid, &tech)
					TagAlertWithActors(id, tid, tech)
				}
				rows.Close()
			}
			time.Sleep(15 * time.Minute)
		}
	}()
}
