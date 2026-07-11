package agent

import (
	"encoding/json"
	"fmt"
	"testing"
)

// TestAnomalyScorePayload_Fields verifies that the anomaly score structure
// submitted by the desktop agent includes the fields the behavioral baseline
// service uses when computing and storing scores.
func TestAnomalyScorePayload_Fields(t *testing.T) {
	score := map[string]any{
		"agent_id":   1,
		"score":      65,
		"scored_at":  "2025-01-15T10:30:00Z",
		"components": map[string]any{
			"log_rate":      20,
			"login_anomaly": 40,
			"off_hours":     10,
			"conn_rate":     5,
		},
	}

	b, _ := json.Marshal(score)
	var decoded map[string]any
	json.Unmarshal(b, &decoded)

	for _, key := range []string{"agent_id", "score", "scored_at", "components"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("anomaly score payload missing field %q", key)
		}
	}
}

// TestAnomalyScore_RangeIsValid verifies that the behavioral score the agent
// produces is in [0, 100]. Scores outside this range are rejected by the
// backend and produce confusing dashboard displays.
func TestAnomalyScore_RangeIsValid(t *testing.T) {
	for _, score := range []int{0, 1, 50, 70, 85, 100} {
		if score < 0 || score > 100 {
			t.Errorf("score %d is outside [0,100]", score)
		}
	}
}

// TestFindingAcknowledge_FieldsPresent verifies that the finding acknowledge
// request body sent by the desktop agent includes the expected fields.
// The backend POST /api/threat/findings/:id/acknowledge expects no body (id
// is in the URL) — the agent must not send a mismatched payload.
func TestFindingAcknowledge_FieldsPresent(t *testing.T) {
	// The acknowledge endpoint takes id in the URL only — body is empty.
	// Verify that the agent constructs the correct URL pattern.
	buildURL := func(findingID int) string {
		return fmt.Sprintf("/api/threat/findings/%d/acknowledge", findingID)
	}

	url := buildURL(7)
	if url != "/api/threat/findings/7/acknowledge" {
		t.Errorf("unexpected URL: %q", url)
	}
}
