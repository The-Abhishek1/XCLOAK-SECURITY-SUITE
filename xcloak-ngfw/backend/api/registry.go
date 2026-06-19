package api

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

// ReceiveRegistry — POST /api/agents/registry  (agent auth)
// Receives Windows registry persistence key snapshots from the agent.
func ReceiveRegistry(c *gin.Context) {

	var entries []models.RegistryEntry
	if err := c.ShouldBindJSON(&entries); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if len(entries) == 0 {
		c.JSON(http.StatusOK, gin.H{"message": "no entries"})
		return
	}

	saved := 0
	for i := range entries {
		entries[i].ThreatTag = classifyRegistryEntry(entries[i])
		_, err := database.DB.Exec(`
			INSERT INTO registry_entries (agent_id, hive, key_path, name, type, data, threat_tag)
			VALUES ($1,$2,$3,$4,$5,$6,$7)
			ON CONFLICT (agent_id, hive, key_path, name)
			DO UPDATE SET type=EXCLUDED.type, data=EXCLUDED.data,
			              threat_tag=EXCLUDED.threat_tag, created_at=NOW()
		`,
			entries[i].AgentID, entries[i].Hive, entries[i].KeyPath,
			entries[i].Name, entries[i].Type, entries[i].Data, entries[i].ThreatTag,
		)
		if err == nil {
			saved++
		}
	}

	// Fire alerts for any newly suspicious entries.
	for _, e := range entries {
		if e.ThreatTag != "" {
			services.CreateAlertFromRegistryEntry(e)
		}
	}

	c.JSON(http.StatusOK, gin.H{"saved": saved})
}

// GetRegistryEntries — GET /api/agents/:id/registry  (user auth)
func GetRegistryEntries(c *gin.Context) {
	agentID := c.Param("id")

	rows, err := database.DB.Query(`
		SELECT id, agent_id, hive, key_path, name, type, data, threat_tag, created_at
		FROM registry_entries
		WHERE agent_id = $1
		ORDER BY created_at DESC
		LIMIT 1000
	`, agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var entries []models.RegistryEntry
	for rows.Next() {
		var e models.RegistryEntry
		rows.Scan(&e.ID, &e.AgentID, &e.Hive, &e.KeyPath, &e.Name, &e.Type, &e.Data, &e.ThreatTag, &e.CreatedAt)
		entries = append(entries, e)
	}
	c.JSON(http.StatusOK, entries)
}

// classifyRegistryEntry flags suspicious registry values.
// T1547.001 — run key points to temp/suspicious path
// T1546.012 — IFEO debugger hijacking
// T1546.010 — AppInit_DLLs injection
func classifyRegistryEntry(e models.RegistryEntry) string {
	data := strings.ToLower(e.Data)
	key  := strings.ToLower(e.KeyPath)
	name := strings.ToLower(e.Name)

	// IFEO debugger hijacking (T1546.012)
	if strings.Contains(key, "image file execution options") && name == "debugger" {
		return "ifeo_hijack"
	}

	// AppInit_DLLs (T1546.010)
	if strings.Contains(key, "windows") && name == "appinit_dlls" && e.Data != "" {
		return "appinit_dll"
	}

	// Winlogon hijacking (T1547.004)
	if strings.Contains(key, "winlogon") &&
		(name == "userinit" || name == "shell") &&
		!strings.Contains(data, "userinit.exe") &&
		!strings.Contains(data, "explorer.exe") {
		return "winlogon_hijack"
	}

	// Run keys pointing to suspicious locations (T1547.001)
	if strings.Contains(key, "currentversion\\run") {
		if matchAnyStr(data, `\temp\`, `\tmp\`, `\appdata\roaming\`, `/tmp/`,
			`\users\public\`, `\programdata\microsoft\`, `powershell`, `cmd /c`,
			`wscript`, `cscript`, `mshta`, `regsvr32`, `rundll32`, `certutil`) {
			return "run_key_suspicious"
		}
	}

	// Boot execute (T1547.001)
	if strings.Contains(key, "session manager") && name == "bootexecute" &&
		e.Data != "autocheck autochk *" {
		return "boot_execute_tamper"
	}

	return fmt.Sprintf("%s", "") // benign — empty tag
}

func matchAnyStr(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
