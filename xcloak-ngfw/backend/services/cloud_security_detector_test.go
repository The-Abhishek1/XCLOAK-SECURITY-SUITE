package services

import (
	"strings"
	"testing"
)

// ── Signature table sanity checks ─────────────────────────────────────────────

func TestCloudSigs_AllProvidersCovered(t *testing.T) {
	providers := map[string]int{}
	for _, s := range cloudSigs {
		providers[s.provider]++
	}
	for _, p := range []string{"aws", "azure", "gcp"} {
		if providers[p] == 0 {
			t.Errorf("provider %q has no signatures", p)
		}
	}
}

func TestCloudSigs_NoDuplicateEventFrag(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range cloudSigs {
		key := s.provider + ":" + strings.ToLower(s.eventFrag)
		if seen[key] {
			t.Errorf("duplicate signature key: %q", key)
		}
		seen[key] = true
	}
}

func TestCloudSigs_AllHaveRequiredFields(t *testing.T) {
	for i, s := range cloudSigs {
		if s.provider == "" {
			t.Errorf("sig[%d] empty provider", i)
		}
		if s.eventFrag == "" {
			t.Errorf("sig[%d] empty eventFrag", i)
		}
		if s.ruleName == "" {
			t.Errorf("sig[%d] empty ruleName", i)
		}
		if s.severity == "" {
			t.Errorf("sig[%d] empty severity", i)
		}
		if s.mitre == "" {
			t.Errorf("sig[%d] empty mitre", i)
		}
		validSeverity := map[string]bool{"low": true, "medium": true, "high": true, "critical": true}
		if !validSeverity[s.severity] {
			t.Errorf("sig[%d] invalid severity %q", i, s.severity)
		}
	}
}

func TestCloudSigs_NewCategoriesCovered(t *testing.T) {
	// Verify that all newly added capability areas have at least one signature.
	type check struct {
		desc      string
		predicate func(s cloudSig) bool
	}
	checks := []check{
		{"AWS Secrets Manager", func(s cloudSig) bool {
			return s.provider == "aws" && strings.Contains(s.eventFrag, "getsecretvalue")
		}},
		{"AWS Lambda persistence", func(s cloudSig) bool {
			return s.provider == "aws" && strings.Contains(s.eventFrag, "createfunction")
		}},
		{"AWS snapshot exfil", func(s cloudSig) bool {
			return s.provider == "aws" && strings.Contains(s.eventFrag, "modifysnapshotattribute")
		}},
		{"AWS VPC Flow Logs deletion", func(s cloudSig) bool {
			return s.provider == "aws" && strings.Contains(s.eventFrag, "deleteflowlogs")
		}},
		{"AWS KMS key destruction", func(s cloudSig) bool {
			return s.provider == "aws" && strings.Contains(s.eventFrag, "schedulekeydeletion")
		}},
		{"Azure container registry", func(s cloudSig) bool {
			return s.provider == "azure" && strings.Contains(s.eventFrag, "registries/write")
		}},
		{"Azure function app", func(s cloudSig) bool {
			return s.provider == "azure" && strings.Contains(s.eventFrag, "sites/write")
		}},
		{"Azure automation runbook", func(s cloudSig) bool {
			return s.provider == "azure" && strings.Contains(s.eventFrag, "runbooks/write")
		}},
		{"Azure elevation of access", func(s cloudSig) bool {
			return s.provider == "azure" && strings.Contains(s.eventFrag, "elevateaccess")
		}},
		{"Azure app credential", func(s cloudSig) bool {
			return s.provider == "azure" && strings.Contains(s.eventFrag, "credentials/write")
		}},
		{"GCP Secret Manager", func(s cloudSig) bool {
			return s.provider == "gcp" && strings.Contains(s.eventFrag, "secretmanager")
		}},
		{"GCP Cloud Function", func(s cloudSig) bool {
			return s.provider == "gcp" && strings.Contains(s.eventFrag, "cloudfunctions")
		}},
		{"GCP Cloud Run", func(s cloudSig) bool {
			return s.provider == "gcp" && strings.Contains(s.eventFrag, "run.services")
		}},
		{"GCP GKE cluster", func(s cloudSig) bool {
			return s.provider == "gcp" && strings.Contains(s.eventFrag, "container.clusters")
		}},
		{"GCP org policy", func(s cloudSig) bool {
			return s.provider == "gcp" && strings.Contains(s.eventFrag, "orgpolicy")
		}},
		{"GCP BigQuery public", func(s cloudSig) bool {
			return s.provider == "gcp" && strings.Contains(s.eventFrag, "bigquery")
		}},
	}

	for _, c := range checks {
		found := false
		for _, s := range cloudSigs {
			if c.predicate(s) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("missing signature for: %s", c.desc)
		}
	}
}

// ── cloudTactic mapping ───────────────────────────────────────────────────────

func TestCloudTactic_Mapping(t *testing.T) {
	cases := []struct {
		mitre string
		want  string
	}{
		{"T1098", "Persistence"},
		{"T1098.001", "Persistence"},
		{"T1136.003", "Persistence"},
		{"T1562.008", "Defense Evasion"},
		{"T1578.002", "Defense Evasion"},
		{"T1530", "Collection"},
		{"T1537", "Collection"},
		{"T1552.001", "Credential Access"},
		{"T1648", "Execution"},
		{"T1610", "Execution"},
		{"T1613", "Execution"},
		{"T1059", "Execution"},
		{"T1485", "Impact"},
		{"T1489", "Impact"},
		{"T1087.004", "Discovery"},
	}
	for _, c := range cases {
		got := cloudTactic(c.mitre)
		if got != c.want {
			t.Errorf("cloudTactic(%q) = %q, want %q", c.mitre, got, c.want)
		}
	}
}

// ── Signature matching logic ──────────────────────────────────────────────────

func TestCloudSigMatch_CaseInsensitive(t *testing.T) {
	// eventFrag matching must be case-insensitive.
	eventName := "DeleteWebACL" // mixed case as it arrives from CloudTrail
	matched := false
	for _, sig := range cloudSigs {
		if sig.provider == "aws" && strings.Contains(strings.ToLower(eventName), strings.ToLower(sig.eventFrag)) {
			matched = true
			if sig.mitre != "T1562.007" {
				t.Errorf("DeleteWebACL should map to T1562.007, got %s", sig.mitre)
			}
			break
		}
	}
	if !matched {
		t.Error("DeleteWebACL should match a cloud signature")
	}
}

func TestCloudSigMatch_UnknownEvent_NoMatch(t *testing.T) {
	eventName := "DescribeVpcs" // intentionally not in the signature list
	for _, sig := range cloudSigs {
		if sig.provider == "aws" && strings.Contains(strings.ToLower(eventName), strings.ToLower(sig.eventFrag)) {
			t.Errorf("DescribeVpcs should not match any signature, matched %q", sig.ruleName)
		}
	}
}

func TestCloudSigMatch_CriticalSeverityEvents(t *testing.T) {
	// All of these must be present at critical severity — they are the most
	// impactful single-event defenses a cloud attacker would try to disable.
	criticalEvents := []struct {
		provider  string
		eventFrag string
	}{
		{"aws", "stoplogging"},
		{"aws", "deletetrail"},
		{"aws", "deletedetector"},
		{"aws", "deleteflowlogs"},
		{"aws", "schedulekeydeletion"},
		{"aws", "stopconfigurationrecorder"},
		{"azure", "diagnosticsettings/delete"},
		{"azure", "authorization/elevateaccess"},
		{"gcp", "configservicev2.updatesink"},
		{"gcp", "orgpolicy.policy.set"},
	}

	critMap := map[string]bool{}
	for _, s := range cloudSigs {
		if s.severity == "critical" {
			critMap[s.provider+":"+strings.ToLower(s.eventFrag)] = true
		}
	}

	for _, e := range criticalEvents {
		key := e.provider + ":" + strings.ToLower(e.eventFrag)
		if !critMap[key] {
			t.Errorf("expected critical severity for %q", key)
		}
	}
}
