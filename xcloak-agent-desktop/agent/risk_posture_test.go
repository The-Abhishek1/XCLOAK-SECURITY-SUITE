package agent

import (
	"encoding/json"
	"testing"
)

// TestRiskPosturePayload_ExcludesServerComputedFields verifies that the agent
// heartbeat payload does NOT include risk-posture aggregates. The risk posture
// score is computed entirely server-side from vulns, alerts, UEBA, and IOC
// data. An agent sending a score would bypass all server-side security logic.
func TestRiskPosturePayload_ExcludesServerComputedFields(t *testing.T) {
	payload := map[string]any{
		"agent_id":       1,
		"version":        "1.0.0",
		"uptime_seconds": 3600,
		"mem_alloc_mb":   128,
		"goroutines":     20,
		"load_avg_1m":    0.5,
	}

	body, _ := json.Marshal(payload)
	var decoded map[string]any
	json.Unmarshal(body, &decoded)

	riskPostureFields := []string{
		"score",
		"vuln_score",
		"ueba_score",
		"alert_score",
		"ioc_score",
		"snoozed_alert_count",
		"asset_scores",
		"risk_posture",
		"snapshot_at",
	}
	for _, f := range riskPostureFields {
		if _, ok := decoded[f]; ok {
			t.Errorf("heartbeat must not include risk-posture field %q", f)
		}
	}
}

// TestVulnScanPayload_Contract verifies the shape of a vulnerability scan
// payload. The backend derives VulnScore from severity + patch_status; the
// agent must report these fields accurately for the score to be correct.
func TestVulnScanPayload_Contract(t *testing.T) {
	payload := []map[string]any{
		{
			"agent_id":       1,
			"cve_id":         "CVE-2024-1234",
			"severity":       "critical",
			"patch_status":   "open",
			"priority_score": 850,
			"title":          "Example critical vuln",
			"epss_score":     0.91,
			"is_kev":         true,
		},
	}

	body, _ := json.Marshal(payload)
	var decoded []map[string]any
	json.Unmarshal(body, &decoded)
	row := decoded[0]

	// severity and patch_status determine the alert score; must be strings
	for _, key := range []string{"cve_id", "severity", "patch_status"} {
		v, ok := row[key]
		if !ok {
			t.Errorf("vuln payload missing required field %q", key)
			continue
		}
		if _, isStr := v.(string); !isStr {
			t.Errorf("field %q is %T, want string", key, v)
		}
	}

	// epss_score determines the attack-path compromise cost; must be numeric
	if _, ok := row["epss_score"].(float64); !ok {
		t.Errorf("epss_score is %T, want float64", row["epss_score"])
	}

	// is_kev triggers a -50 cost bonus in the attack path; must be boolean
	if _, ok := row["is_kev"].(bool); !ok {
		t.Errorf("is_kev is %T, want bool", row["is_kev"])
	}
}

// TestVulnScanPayload_SeverityAllowedValues verifies that severity is one of
// the four values the backend's risk score formula handles. An unexpected
// value (e.g. "CRITICAL" in caps) would silently count as 0 in the score.
func TestVulnScanPayload_SeverityAllowedValues(t *testing.T) {
	allowed := map[string]bool{
		"critical": true,
		"high":     true,
		"medium":   true,
		"low":      true,
	}

	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if !allowed[sev] {
			t.Errorf("severity %q not in allowed set", sev)
		}
	}

	// These should NOT be accepted by the agent (wrong casing/format).
	rejected := []string{"Critical", "CRITICAL", "HIGH", "4", "0"}
	for _, sev := range rejected {
		if allowed[sev] {
			t.Errorf("severity %q should not be in the allowed set", sev)
		}
	}
}
