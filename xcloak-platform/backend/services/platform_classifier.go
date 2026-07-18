package services

// Platform classifier — derives a normalised platform_category from the raw
// OS string that agents self-report, plus asset_type for non-agent assets.
//
// Categories:
//   windows  — any Windows edition (Desktop, Server, Embedded, IoT Core)
//   linux    — any Linux distro (Ubuntu, Debian, RHEL, CentOS, Amazon, Kali…)
//   macos    — macOS / Darwin
//   ios      — Apple iOS / iPadOS / iPhone OS
//   android  — Android (AOSP or vendor)
//   network  — routers, switches, firewalls, load balancers, network appliances
//   web      — web-application tier or web server (manually tagged)
//   cloud    — cloud-native VMs, containers, serverless — set via asset_type
//   iot      — IoT / embedded devices
//   other    — unrecognised / not reported
//
// The classifier runs:
//   • At agent registration (RegisterAgent in agent_repository.go calls
//     ClassifyOS and writes platform_category in the same transaction).
//   • At every heartbeat (UpdateAgentPlatform).
//   • On a 6-hour scheduler for any agent whose category is still 'other'.

import (
	"log"
	"strings"
	"time"

	"xcloak-platform/database"
)

// ClassifyOS maps a raw OS string to a canonical platform_category.
// The match is case-insensitive; the first rule that fires wins.
func ClassifyOS(os string) string {
	s := strings.ToLower(strings.TrimSpace(os))
	if s == "" {
		return "other"
	}

	type rule struct {
		keywords []string
		category string
	}
	rules := []rule{
		// Specific Apple mobile prefixes — must come before any "ios" substring check
		{[]string{"iphone os", "ipad os", "ipados"}, "ios"},
		// Android
		{[]string{"android"}, "android"},
		// Windows (all flavours)
		{[]string{"windows"}, "windows"},
		// macOS / Darwin
		{[]string{"darwin", "macos", "mac os x", "mac os"}, "macos"},
		// Network appliances — must come BEFORE the bare "ios " check because
		// "cisco ios", "fortios", etc. all contain the substring "ios".
		{[]string{
			"cisco ios", "junos", "arista eos", "panos", "pan-os",
			"fortios", "arubaos", "routeros", "mikrotik", "vyos",
			"opnsense", "pfsense", "checkpoint", "f5 tmos",
		}, "network"},
		// Linux distros — ordered so specific names match before generic "linux"
		{[]string{
			"ubuntu", "debian", "centos", "rhel", "red hat",
			"fedora", "kali", "parrot", "arch linux", "manjaro",
			"opensuse", "suse", "amazon linux", "oracle linux",
			"alpine", "gentoo", "slackware", "rocky", "almalinux",
			"raspbian", "armbian", "linux",
		}, "linux"},
		// Cloud (common cloud-init / hypervisor identifiers)
		{[]string{
			"amazon ec2", "azure vm", "google compute", "cloud-init",
		}, "cloud"},
		// IoT
		{[]string{"freertos", "zephyr", "contiki", "riot os", "mbed"}, "iot"},
		// Bare Apple "iOS 16.6" string — after all network patterns so
		// "fortios" and "cisco ios" are already caught above.
		{[]string{"ios "}, "ios"},
	}

	for _, r := range rules {
		for _, kw := range r.keywords {
			if strings.Contains(s, kw) {
				return r.category
			}
		}
	}
	return "other"
}

// ClassifyAssetType maps an asset_type string (when no agent is linked) to
// a platform_category. Assets linked to an agent inherit the agent's category.
func ClassifyAssetType(assetType string) string {
	s := strings.ToLower(strings.TrimSpace(assetType))
	switch s {
	case "web_server", "web_application", "web":
		return "web"
	case "network_device", "firewall", "router", "switch", "load_balancer", "network":
		return "network"
	case "cloud_instance", "cloud", "container", "serverless":
		return "cloud"
	case "iot_device", "iot", "embedded":
		return "iot"
	case "mobile_ios", "ios":
		return "ios"
	case "mobile_android", "android":
		return "android"
	default:
		return "other"
	}
}

// UpdateAgentPlatform writes the derived platform_category for one agent.
// Called after registration and heartbeat.
func UpdateAgentPlatform(agentID int, os string) {
	category := ClassifyOS(os)
	database.DB.Exec(
		`UPDATE agents SET platform_category = $1 WHERE id = $2`,
		category, agentID,
	)
}

// SyncAssetPlatformCategory back-fills assets whose platform_category is
// still 'other'. For assets with an agent: inherit the agent's category.
// For unlinked assets: derive from asset_type.
func SyncAssetPlatformCategory(tenantID int) {
	// Inherit from linked agents.
	database.DB.Exec(`
		UPDATE assets a
		SET platform_category = ag.platform_category
		FROM agents ag
		WHERE ag.id = a.agent_id
		  AND a.tenant_id = $1
		  AND ag.platform_category <> 'other'
		  AND a.platform_category = 'other'
	`, tenantID)

	// Derive from asset_type for unlinked assets.
	rows, err := database.RDB().Query(`
		SELECT id, asset_type FROM assets
		WHERE tenant_id = $1 AND platform_category = 'other'
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var assetType string
		if rows.Scan(&id, &assetType) != nil {
			continue
		}
		cat := ClassifyAssetType(assetType)
		if cat != "other" {
			database.DB.Exec(
				`UPDATE assets SET platform_category = $1 WHERE id = $2`,
				cat, id,
			)
		}
	}
}

// GetPlatformSummary returns a breakdown of agent + asset counts by
// platform_category for a tenant. Useful for dashboard inventory widgets.
type PlatformCount struct {
	Category    string `json:"category"`
	AgentCount  int    `json:"agent_count"`
	AssetCount  int    `json:"asset_count"`
	OnlineCount int    `json:"online_count"`
}

func GetPlatformSummary(tenantID int) ([]PlatformCount, error) {
	rows, err := database.RDB().Query(`
		SELECT
			cat,
			SUM(agent_cnt)  AS agent_count,
			SUM(asset_cnt)  AS asset_count,
			SUM(online_cnt) AS online_count
		FROM (
			SELECT platform_category AS cat,
			       COUNT(*)                                  AS agent_cnt,
			       0                                         AS asset_cnt,
			       COUNT(*) FILTER (WHERE status = 'online') AS online_cnt
			FROM agents WHERE tenant_id = $1
			GROUP BY platform_category
			UNION ALL
			SELECT platform_category AS cat,
			       0 AS agent_cnt, COUNT(*) AS asset_cnt, 0 AS online_cnt
			FROM assets WHERE tenant_id = $1
			GROUP BY platform_category
		) sub
		GROUP BY cat
		ORDER BY agent_count DESC, asset_count DESC
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []PlatformCount{}
	for rows.Next() {
		var pc PlatformCount
		if rows.Scan(&pc.Category, &pc.AgentCount, &pc.AssetCount, &pc.OnlineCount) != nil {
			continue
		}
		out = append(out, pc)
	}
	return out, nil
}

// StartPlatformClassificationScheduler runs every 6 hours to catch any
// agents/assets that slipped through with category='other'.
func StartPlatformClassificationScheduler() {
	go func() {
		time.Sleep(90 * time.Second) // stagger from other schedulers

		run := func() {
			// Re-classify agents whose OS string was empty at registration.
			rows, err := database.DB.Query(`
				SELECT id, COALESCE(os,'') FROM agents
				WHERE platform_category = 'other' AND os IS NOT NULL AND os <> ''
			`)
			if err == nil {
				defer rows.Close()
				for rows.Next() {
					var id int
					var os string
					if rows.Scan(&id, &os) == nil {
						UpdateAgentPlatform(id, os)
					}
				}
			}

			// Sync assets per tenant.
			tRows, err := database.DB.Query(
				`SELECT id FROM tenants WHERE is_active = true`)
			if err != nil {
				return
			}
			defer tRows.Close()
			for tRows.Next() {
				var tid int
				if tRows.Scan(&tid) == nil {
					SyncAssetPlatformCategory(tid)
				}
			}
		}
		run()
		for {
			time.Sleep(6 * time.Hour)
			run()
		}
	}()
	log.Println("[PlatformClassifier] scheduler started (6h interval)")
}
