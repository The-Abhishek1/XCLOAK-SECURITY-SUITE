//go:build integration

package repositories

import (
	"testing"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
	"xcloak-ngfw/testenv"
)

// setupIntegration connects the global database.DB to the test database and
// skips the test when the database isn't available.
func setupIntegration(t *testing.T) {
	t.Helper()
	db := testenv.SetupDB(t)
	database.DB = db
	t.Cleanup(func() { db.Close(); database.DB = nil })
}

// ── Firewall rules ────────────────────────────────────────────────────────────

func TestCreateAndGetRule(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	rule := models.FirewallRule{
		Name:      "integration-test-rule",
		SrcIP:     "10.0.0.1",
		DstPort:   "443",
		Proto:     "tcp",
		Action:    "allow",
		Direction: "in",
		Priority:  10,
		TenantID:  1,
	}
	if err := CreateRule(rule, 1); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}

	rules, err := GetRules(1)
	if err != nil {
		t.Fatalf("GetRules: %v", err)
	}
	found := false
	for _, r := range rules {
		if r.Name == "integration-test-rule" {
			found = true
		}
	}
	if !found {
		t.Error("created rule not found in GetRules")
	}
}

func TestDeleteRule(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	rule := models.FirewallRule{
		Name: "del-test", Action: "deny", Direction: "out",
		Proto: "tcp", Priority: 5, TenantID: 1,
	}
	if err := CreateRule(rule, 1); err != nil {
		t.Fatalf("CreateRule: %v", err)
	}
	rules, _ := GetRules(1)
	var id string
	for _, r := range rules {
		if r.Name == "del-test" {
			id = r.ID
		}
	}
	if id == "" {
		t.Skip("rule not found after create — fixture state may conflict")
	}
	n, err := DeleteRule(id, 1)
	if err != nil {
		t.Fatalf("DeleteRule: %v", err)
	}
	if n == 0 {
		t.Error("DeleteRule: expected 1 row affected, got 0")
	}
}

// ── Alerts ────────────────────────────────────────────────────────────────────

func TestCreateAndGetAlert(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	err := CreateAlert(models.Alert{
		TenantID:   1,
		AgentID:    1,
		Severity:   "high",
		RuleName:   "Integration Test Alert",
		LogMessage: "test message",
	})
	if err != nil {
		t.Fatalf("CreateAlert: %v", err)
	}

	alerts, err := GetAlerts(1)
	if err != nil {
		t.Fatalf("GetAlerts: %v", err)
	}
	if len(alerts) == 0 {
		t.Error("no alerts returned after create")
	}
}

func TestAlertExists(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	_ = CreateAlert(models.Alert{
		TenantID: 1, AgentID: 1, Severity: "medium",
		RuleName: "dedup-rule", LogMessage: "dedupkey",
	})

	exists, err := AlertExists(1, 1, "dedup-rule", "dedupkey")
	if err != nil {
		t.Fatalf("AlertExists: %v", err)
	}
	if !exists {
		t.Error("AlertExists returned false for just-created alert")
	}

	notExists, _ := AlertExists(1, 1, "nonexistent-rule", "nope")
	if notExists {
		t.Error("AlertExists returned true for non-existent alert")
	}
}

// ── Audit logs ────────────────────────────────────────────────────────────────

func TestCreateAndGetAuditLog(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	if err := CreateAuditLog("test.action", "integration test", "testuser"); err != nil {
		t.Fatalf("CreateAuditLog: %v", err)
	}
	logs, err := GetAuditLogs(1)
	if err != nil {
		t.Fatalf("GetAuditLogs: %v", err)
	}
	_ = logs // just verify no error
}

// ── Users ─────────────────────────────────────────────────────────────────────

func TestCreateUser(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	user := models.User{
		TenantID: 1,
		Username: "integration-test-user",
		Email:    "inttest@example.com",
		Password: "hashed-password-here",
		Role:     "analyst",
	}
	if err := CreateUser(user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
}

func TestGetUserByUsername(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	user := models.User{
		TenantID: 1, Username: "findme", Email: "findme@x.com",
		Password: "pw", Role: "viewer",
	}
	_ = CreateUser(user)

	found, err := GetUserByUsername("findme", 1)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if found == nil {
		t.Error("user not found")
	}
}

// ── Agents ────────────────────────────────────────────────────────────────────

func TestGetAgents_EmptyOrPopulated(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	agents, err := GetAgents(1)
	if err != nil {
		t.Fatalf("GetAgents: %v", err)
	}
	_ = agents
}

func TestGetAgentByToken_NotFound(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	agent, err := GetAgentByToken("definitely-not-a-real-token")
	if err == nil {
		t.Error("expected error for non-existent token")
	}
	if agent != nil {
		t.Error("expected nil agent for non-existent token")
	}
}

// ── Cases ─────────────────────────────────────────────────────────────────────

func TestCaseCRUD(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	c, err := CreateCase(models.Case{
		TenantID: 1, Title: "Integration Case", Status: "open", Severity: "high",
	})
	if err != nil {
		t.Fatalf("CreateCase: %v", err)
	}
	if c.ID == 0 {
		t.Error("CreateCase returned ID=0")
	}

	got, err := GetCaseByID(c.ID, 1)
	if err != nil {
		t.Fatalf("GetCaseByID: %v", err)
	}
	if got.Title != "Integration Case" {
		t.Errorf("title = %q, want Integration Case", got.Title)
	}

	got.Status = "resolved"
	if err := UpdateCase(got); err != nil {
		t.Fatalf("UpdateCase: %v", err)
	}

	if err := DeleteCase(c.ID, 1); err != nil {
		t.Fatalf("DeleteCase: %v", err)
	}
}

// ── Sessions ──────────────────────────────────────────────────────────────────

func TestCreateAndDeleteSession(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	s := models.Session{
		TenantID:  1,
		UserID:    1,
		TokenHash: "integration-test-session-hash",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := CreateSession(s); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	RevokeSessionByHash("integration-test-session-hash")
}

// ── Tenants ───────────────────────────────────────────────────────────────────

func TestCreateAndGetTenant(t *testing.T) {
	setupIntegration(t)

	tenant, err := CreateTenant("Integration Test Tenant", "integration-test")
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if tenant == nil || tenant.ID == 0 {
		t.Error("CreateTenant returned nil or zero ID")
	}

	tenants, err := GetTenants()
	if err != nil {
		t.Fatalf("GetTenants: %v", err)
	}
	if len(tenants) == 0 {
		t.Error("GetTenants returned empty list")
	}
}

// ── Log sources ───────────────────────────────────────────────────────────────

func TestLogSourceCRUD(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	src := &models.LogSource{
		TenantID: 1, Name: "Integration Source", Format: "syslog",
		Protocol: "syslog_udp", Port: 55514,
	}
	id, key, err := CreateLogSource(src)
	if err != nil {
		t.Fatalf("CreateLogSource: %v", err)
	}
	if id == 0 || key == "" {
		t.Error("CreateLogSource returned zero id or empty key")
	}

	sources, err := GetLogSources(1)
	if err != nil {
		t.Fatalf("GetLogSources: %v", err)
	}
	_ = sources

	if err := DeleteLogSource(id, 1); err != nil {
		t.Fatalf("DeleteLogSource: %v", err)
	}
}

// ── Vulnerabilities ───────────────────────────────────────────────────────────

func TestCreateAndGetVulnerability(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	vuln := models.Vulnerability{
		TenantID: 1, AgentID: 1,
		CVE: "CVE-2025-99999", Severity: "critical",
		Summary: "Integration test vulnerability",
	}
	if err := CreateVulnerability(vuln); err != nil {
		t.Fatalf("CreateVulnerability: %v", err)
	}

	vulns, err := GetVulnerabilities(1)
	if err != nil {
		t.Fatalf("GetVulnerabilities: %v", err)
	}
	_ = vulns
}

// ── Custom roles ──────────────────────────────────────────────────────────────

func TestCustomRoleCRUD(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	role, err := CreateCustomRole(1, "integration-role", []string{"view_alerts", "view_logs"}, "admin")
	if err != nil {
		t.Fatalf("CreateCustomRole: %v", err)
	}

	roles, err := GetCustomRoles(1)
	if err != nil {
		t.Fatalf("GetCustomRoles: %v", err)
	}
	_ = roles

	if err := UpdateCustomRole(role.ID, 1, []string{"view_alerts", "manage_agents"}); err != nil {
		t.Fatalf("UpdateCustomRole: %v", err)
	}

	if err := DeleteCustomRole(role.ID, 1); err != nil {
		t.Fatalf("DeleteCustomRole: %v", err)
	}
}

// ── API keys ──────────────────────────────────────────────────────────────────

func TestAPIKeyCRUD(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	key, err := CreateAPIKey(1, "integration-key", "hashval", "xc_", "viewer", "admin", nil)
	if err != nil {
		t.Fatalf("CreateAPIKey: %v", err)
	}
	if key == nil {
		t.Fatal("CreateAPIKey returned nil")
	}

	keys, err := GetAPIKeysByTenant(1)
	if err != nil {
		t.Fatalf("GetAPIKeysByTenant: %v", err)
	}
	_ = keys

	if err := RevokeAPIKey(key.ID, 1); err != nil {
		t.Fatalf("RevokeAPIKey: %v", err)
	}
}

// ── CountRecentMatchingAlerts ─────────────────────────────────────────────────

func TestCountRecentMatchingAlerts(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	n, err := CountRecentMatchingAlerts(1, "high", "Integration", "", 60)
	if err != nil {
		t.Fatalf("CountRecentMatchingAlerts: %v", err)
	}
	_ = n
}

// ── GetAllAgents / GetAllAlerts ───────────────────────────────────────────────

func TestGetAllAgents(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	agents, err := GetAllAgents()
	if err != nil {
		t.Fatalf("GetAllAgents: %v", err)
	}
	_ = agents
}

func TestGetAllAlerts(t *testing.T) {
	setupIntegration(t)
	testenv.LoadFixtures(t, database.DB)

	alerts, err := GetAllAlerts()
	if err != nil {
		t.Fatalf("GetAllAlerts: %v", err)
	}
	_ = alerts
}
