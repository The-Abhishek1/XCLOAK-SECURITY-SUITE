package services

// MDM (Mobile Device Management) service.
//
// Covers:
//   • Device enrollment / inventory
//   • Compliance policy evaluation (8 rule types)
//   • Remote command queue (lock, wipe, sync, push_profile, …)
//   • Configuration profile management and deployment tracking
//
// What this layer does NOT do:
//   Apple APNS and Android FCM push delivery require certificates and
//   vendor API credentials. DeliverPendingCommands() marks commands "sent"
//   and logs them; actual push is wired externally. The data model and
//   queue mechanics are fully implemented — plugging in APNS/FCM is a
//   one-function swap of deliverViaPush().
//
// Compliance rule types:
//   encryption_required     is_encrypted = true
//   passcode_required       has_passcode = true
//   jailbreak_not_allowed   is_jailbroken = false
//   developer_mode_off      developer_mode_on = false
//   firewall_required       firewall_enabled = true
//   min_os_version          os_version >= value  (semver-aware)
//   enrollment_type_req     enrollment_type == value
//   supervised_required     is_supervised = true

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"xcloak-platform/database"
)

// ── Domain types ──────────────────────────────────────────────────────────────

type MDMDevice struct {
	ID                 int        `json:"id"`
	TenantID           int        `json:"tenant_id"`
	AgentID            *int       `json:"agent_id,omitempty"`
	UDID               string     `json:"udid"`
	SerialNumber       string     `json:"serial_number"`
	DeviceName         string     `json:"device_name"`
	Model              string     `json:"model"`
	Platform           string     `json:"platform"`
	OSVersion          string     `json:"os_version"`
	BuildVersion       string     `json:"build_version"`
	OwnerEmail         string     `json:"owner_email"`
	EnrollmentType     string     `json:"enrollment_type"`
	IsSupervised       bool       `json:"is_supervised"`
	IsPersonal         bool       `json:"is_personal"`
	EnrolledAt         time.Time  `json:"enrolled_at"`
	LastCheckIn        *time.Time `json:"last_check_in,omitempty"`
	Status             string     `json:"status"`
	IsEncrypted        *bool      `json:"is_encrypted,omitempty"`
	HasPasscode        *bool      `json:"has_passcode,omitempty"`
	PasscodeCompliant  *bool      `json:"passcode_compliant,omitempty"`
	IsJailbroken       bool       `json:"is_jailbroken"`
	DeveloperModeOn    bool       `json:"developer_mode_on"`
	FirewallEnabled    *bool      `json:"firewall_enabled,omitempty"`
	ComplianceStatus   string     `json:"compliance_status"`
	ComplianceCheckedAt *time.Time `json:"compliance_checked_at,omitempty"`
	PushToken          string     `json:"push_token,omitempty"`
}

type MDMPolicy struct {
	ID          int      `json:"id"`
	TenantID    int      `json:"tenant_id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Platforms   []string `json:"platforms"`
	IsActive    bool     `json:"is_active"`
	Rules       []MDMPolicyRule `json:"rules,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type MDMPolicyRule struct {
	ID       int    `json:"id"`
	PolicyID int    `json:"policy_id"`
	RuleType string `json:"rule_type"`
	Value    string `json:"value"`
	Severity string `json:"severity"`
}

type MDMComplianceResult struct {
	RuleID      int    `json:"rule_id"`
	RuleType    string `json:"rule_type"`
	Status      string `json:"status"`
	ActualValue string `json:"actual_value"`
	Severity    string `json:"severity"`
	CheckedAt   time.Time `json:"checked_at"`
}

type MDMCommand struct {
	ID             int            `json:"id"`
	TenantID       int            `json:"tenant_id"`
	DeviceID       int            `json:"device_id"`
	CommandType    string         `json:"command_type"`
	Payload        map[string]any `json:"payload"`
	Status         string         `json:"status"`
	QueuedBy       *int           `json:"queued_by,omitempty"`
	QueuedAt       time.Time      `json:"queued_at"`
	SentAt         *time.Time     `json:"sent_at,omitempty"`
	AcknowledgedAt *time.Time     `json:"acknowledged_at,omitempty"`
	ErrorMsg       string         `json:"error_msg,omitempty"`
}

type MDMProfile struct {
	ID          int       `json:"id"`
	TenantID    int       `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Platform    string    `json:"platform"`
	ProfileType string    `json:"profile_type"`
	Content     string    `json:"content,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ── Device enrollment ─────────────────────────────────────────────────────────

// EnrollDevice inserts or updates a device by (tenant_id, udid).
// Called when a device checks in via the MDM enroll endpoint.
func EnrollDevice(d MDMDevice) (int, error) {
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO mdm_devices
			(tenant_id, agent_id, udid, serial_number, device_name, model,
			 platform, os_version, build_version, owner_email, enrollment_type,
			 is_supervised, is_personal, push_token, status, last_check_in,
			 is_encrypted, has_passcode, passcode_compliant,
			 is_jailbroken, developer_mode_on, firewall_enabled)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'enrolled',NOW(),
		        $15,$16,$17,$18,$19,$20)
		ON CONFLICT (tenant_id, udid) DO UPDATE SET
			serial_number      = EXCLUDED.serial_number,
			device_name        = EXCLUDED.device_name,
			model              = EXCLUDED.model,
			os_version         = EXCLUDED.os_version,
			build_version      = EXCLUDED.build_version,
			owner_email        = COALESCE(NULLIF(EXCLUDED.owner_email,''), mdm_devices.owner_email),
			push_token         = COALESCE(NULLIF(EXCLUDED.push_token,''), mdm_devices.push_token),
			is_encrypted       = COALESCE(EXCLUDED.is_encrypted, mdm_devices.is_encrypted),
			has_passcode       = COALESCE(EXCLUDED.has_passcode, mdm_devices.has_passcode),
			passcode_compliant = COALESCE(EXCLUDED.passcode_compliant, mdm_devices.passcode_compliant),
			is_jailbroken      = EXCLUDED.is_jailbroken,
			developer_mode_on  = EXCLUDED.developer_mode_on,
			firewall_enabled   = COALESCE(EXCLUDED.firewall_enabled, mdm_devices.firewall_enabled),
			status             = 'enrolled',
			last_check_in      = NOW()
		RETURNING id
	`, d.TenantID, d.AgentID, d.UDID, d.SerialNumber, d.DeviceName, d.Model,
		d.Platform, d.OSVersion, d.BuildVersion, d.OwnerEmail, d.EnrollmentType,
		d.IsSupervised, d.IsPersonal, d.PushToken,
		d.IsEncrypted, d.HasPasscode, d.PasscodeCompliant,
		d.IsJailbroken, d.DeveloperModeOn, d.FirewallEnabled,
	).Scan(&id)
	return id, err
}

func UnenrollDevice(deviceID, tenantID int) error {
	_, err := database.DB.Exec(
		`UPDATE mdm_devices SET status='unenrolled' WHERE id=$1 AND tenant_id=$2`,
		deviceID, tenantID,
	)
	return err
}

func BlockDevice(deviceID, tenantID int) error {
	_, err := database.DB.Exec(
		`UPDATE mdm_devices SET status='blocked' WHERE id=$1 AND tenant_id=$2`,
		deviceID, tenantID,
	)
	return err
}

func UnblockDevice(deviceID, tenantID int) error {
	_, err := database.DB.Exec(
		`UPDATE mdm_devices SET status='enrolled' WHERE id=$1 AND tenant_id=$2 AND status='blocked'`,
		deviceID, tenantID,
	)
	return err
}

// GetDevice returns one device scoped to the tenant.
func GetDevice(deviceID, tenantID int) (*MDMDevice, error) {
	row := database.RDB().QueryRow(`
		SELECT id, tenant_id, agent_id, udid, serial_number, device_name, model,
		       platform, os_version, build_version, owner_email, enrollment_type,
		       is_supervised, is_personal, enrolled_at, last_check_in, status,
		       is_encrypted, has_passcode, passcode_compliant,
		       is_jailbroken, developer_mode_on, firewall_enabled,
		       compliance_status, compliance_checked_at, push_token
		FROM mdm_devices WHERE id=$1 AND tenant_id=$2
	`, deviceID, tenantID)
	return scanDevice(row)
}

// ListDevices returns devices for a tenant; optional platform/status filter.
func ListDevices(tenantID int, platform, status, ownerEmail string) ([]MDMDevice, error) {
	q := `
		SELECT id, tenant_id, agent_id, udid, serial_number, device_name, model,
		       platform, os_version, build_version, owner_email, enrollment_type,
		       is_supervised, is_personal, enrolled_at, last_check_in, status,
		       is_encrypted, has_passcode, passcode_compliant,
		       is_jailbroken, developer_mode_on, firewall_enabled,
		       compliance_status, compliance_checked_at, push_token
		FROM mdm_devices
		WHERE tenant_id = $1
	`
	args := []any{tenantID}
	n := 2
	if platform != "" {
		q += fmt.Sprintf(" AND platform = $%d", n)
		args = append(args, platform)
		n++
	}
	if status != "" {
		q += fmt.Sprintf(" AND status = $%d", n)
		args = append(args, status)
		n++
	}
	if ownerEmail != "" {
		q += fmt.Sprintf(" AND LOWER(owner_email) = LOWER($%d)", n)
		args = append(args, ownerEmail)
		n++
	}
	q += " ORDER BY last_check_in DESC NULLS LAST, enrolled_at DESC"

	rows, err := database.RDB().Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []MDMDevice{}
	for rows.Next() {
		d, err := scanDevice(rows)
		if err == nil {
			out = append(out, *d)
		}
	}
	return out, nil
}

type deviceScanner interface {
	Scan(...any) error
}

func scanDevice(s deviceScanner) (*MDMDevice, error) {
	var d MDMDevice
	err := s.Scan(
		&d.ID, &d.TenantID, &d.AgentID, &d.UDID, &d.SerialNumber, &d.DeviceName, &d.Model,
		&d.Platform, &d.OSVersion, &d.BuildVersion, &d.OwnerEmail, &d.EnrollmentType,
		&d.IsSupervised, &d.IsPersonal, &d.EnrolledAt, &d.LastCheckIn, &d.Status,
		&d.IsEncrypted, &d.HasPasscode, &d.PasscodeCompliant,
		&d.IsJailbroken, &d.DeveloperModeOn, &d.FirewallEnabled,
		&d.ComplianceStatus, &d.ComplianceCheckedAt, &d.PushToken,
	)
	return &d, err
}

// ── Policy management ─────────────────────────────────────────────────────────

func CreatePolicy(p MDMPolicy) (int, error) {
	plats := strings.Join(p.Platforms, ",")
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO mdm_policies (tenant_id, name, description, platforms, is_active)
		VALUES ($1,$2,$3,$4::text[],$5)
		RETURNING id
	`, p.TenantID, p.Name, p.Description,
		fmt.Sprintf("{%s}", plats), p.IsActive,
	).Scan(&id)
	if err != nil {
		return 0, err
	}
	for _, r := range p.Rules {
		database.DB.Exec(`
			INSERT INTO mdm_policy_rules (policy_id, rule_type, value, severity)
			VALUES ($1,$2,$3,$4)
		`, id, r.RuleType, r.Value, r.Severity)
	}
	return id, nil
}

func ListPolicies(tenantID int) ([]MDMPolicy, error) {
	rows, err := database.RDB().Query(`
		SELECT p.id, p.tenant_id, p.name, p.description,
		       COALESCE(array_to_string(p.platforms,','),''),
		       p.is_active, p.created_at, p.updated_at
		FROM mdm_policies p
		WHERE p.tenant_id=$1
		ORDER BY p.name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []MDMPolicy{}
	for rows.Next() {
		var p MDMPolicy
		var platStr string
		if rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description,
			&platStr, &p.IsActive, &p.CreatedAt, &p.UpdatedAt) != nil {
			continue
		}
		if platStr != "" {
			p.Platforms = strings.Split(platStr, ",")
		} else {
			p.Platforms = []string{}
		}
		p.Rules = loadPolicyRules(p.ID)
		out = append(out, p)
	}
	return out, nil
}

func loadPolicyRules(policyID int) []MDMPolicyRule {
	rows, err := database.RDB().Query(
		`SELECT id, policy_id, rule_type, value, severity FROM mdm_policy_rules WHERE policy_id=$1`,
		policyID,
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	rules := []MDMPolicyRule{}
	for rows.Next() {
		var r MDMPolicyRule
		if rows.Scan(&r.ID, &r.PolicyID, &r.RuleType, &r.Value, &r.Severity) == nil {
			rules = append(rules, r)
		}
	}
	return rules
}

// ── Compliance engine ─────────────────────────────────────────────────────────

// RunComplianceForTenant evaluates all active policies against all enrolled
// devices for the tenant, upserts results, and updates the per-device rollup.
func RunComplianceForTenant(tenantID int) {
	policies, err := ListPolicies(tenantID)
	if err != nil {
		return
	}
	// Filter to active policies with rules.
	active := []MDMPolicy{}
	for _, p := range policies {
		if p.IsActive && len(p.Rules) > 0 {
			active = append(active, p)
		}
	}
	if len(active) == 0 {
		return
	}

	devices, _ := ListDevices(tenantID, "", "enrolled", "")
	for _, d := range devices {
		runComplianceForDevice(d, active)
	}
}

func runComplianceForDevice(d MDMDevice, policies []MDMPolicy) {
	overallFail := false

	for _, p := range policies {
		if !policyAppliesToDevice(p, d) {
			continue
		}
		for _, rule := range p.Rules {
			status, actual := evaluateRule(d, rule)
			database.DB.Exec(`
				INSERT INTO mdm_compliance_results
					(device_id, policy_id, rule_id, status, actual_value, checked_at)
				VALUES ($1,$2,$3,$4,$5,NOW())
				ON CONFLICT (device_id, rule_id) DO UPDATE SET
					status       = EXCLUDED.status,
					actual_value = EXCLUDED.actual_value,
					checked_at   = NOW()
			`, d.ID, p.ID, rule.ID, status, actual)
			if status == "fail" {
				overallFail = true
			}
		}
	}

	overall := "compliant"
	if overallFail {
		overall = "non_compliant"
	}
	database.DB.Exec(`
		UPDATE mdm_devices
		SET compliance_status=$1, compliance_checked_at=NOW()
		WHERE id=$2
	`, overall, d.ID)
}

func policyAppliesToDevice(p MDMPolicy, d MDMDevice) bool {
	if len(p.Platforms) == 0 {
		return true
	}
	for _, pl := range p.Platforms {
		if strings.EqualFold(pl, d.Platform) {
			return true
		}
	}
	return false
}

// evaluateRule tests one MDMPolicyRule against a device's current attributes.
// Returns ("pass"|"fail"|"unknown", humanReadableActualValue).
func evaluateRule(d MDMDevice, r MDMPolicyRule) (status, actual string) {
	switch r.RuleType {
	case "encryption_required":
		if d.IsEncrypted == nil {
			return "unknown", "not reported"
		}
		if *d.IsEncrypted {
			return "pass", "encrypted"
		}
		return "fail", "not encrypted"

	case "passcode_required":
		if d.HasPasscode == nil {
			return "unknown", "not reported"
		}
		if *d.HasPasscode {
			return "pass", "passcode set"
		}
		return "fail", "no passcode"

	case "jailbreak_not_allowed":
		if d.IsJailbroken {
			return "fail", "jailbroken/rooted"
		}
		return "pass", "not jailbroken"

	case "developer_mode_off":
		if d.DeveloperModeOn {
			return "fail", "developer mode enabled"
		}
		return "pass", "developer mode off"

	case "firewall_required":
		if d.FirewallEnabled == nil {
			return "unknown", "not reported"
		}
		if *d.FirewallEnabled {
			return "pass", "firewall enabled"
		}
		return "fail", "firewall disabled"

	case "supervised_required":
		if d.IsSupervised {
			return "pass", "supervised"
		}
		return "fail", "not supervised"

	case "enrollment_type_req":
		if strings.EqualFold(d.EnrollmentType, r.Value) {
			return "pass", d.EnrollmentType
		}
		return "fail", d.EnrollmentType

	case "min_os_version":
		cmp := compareVersions(d.OSVersion, r.Value)
		if cmp < 0 {
			return "fail", fmt.Sprintf("os %s < required %s", d.OSVersion, r.Value)
		}
		return "pass", fmt.Sprintf("os %s", d.OSVersion)

	default:
		return "unknown", "unsupported rule type"
	}
}

// compareVersions returns -1, 0, or 1 for a vs b (semver-like dot-separated).
func compareVersions(a, b string) int {
	aParts := strings.Split(a, ".")
	bParts := strings.Split(b, ".")
	maxLen := len(aParts)
	if len(bParts) > maxLen {
		maxLen = len(bParts)
	}
	for i := 0; i < maxLen; i++ {
		var av, bv int
		if i < len(aParts) {
			av, _ = strconv.Atoi(strings.TrimSpace(aParts[i]))
		}
		if i < len(bParts) {
			bv, _ = strconv.Atoi(strings.TrimSpace(bParts[i]))
		}
		if av < bv {
			return -1
		}
		if av > bv {
			return 1
		}
	}
	return 0
}

// GetDeviceCompliance returns the per-rule results for a device.
func GetDeviceCompliance(deviceID, tenantID int) ([]MDMComplianceResult, error) {
	// Verify device ownership first.
	var count int
	database.RDB().QueryRow(
		`SELECT COUNT(*) FROM mdm_devices WHERE id=$1 AND tenant_id=$2`,
		deviceID, tenantID,
	).Scan(&count)
	if count == 0 {
		return nil, fmt.Errorf("device not found")
	}

	rows, err := database.RDB().Query(`
		SELECT cr.rule_id, r.rule_type, cr.status, cr.actual_value, r.severity, cr.checked_at
		FROM mdm_compliance_results cr
		JOIN mdm_policy_rules r ON r.id = cr.rule_id
		WHERE cr.device_id = $1
		ORDER BY
			CASE cr.status WHEN 'fail' THEN 1 WHEN 'unknown' THEN 2 ELSE 3 END,
			CASE r.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2
			                WHEN 'medium' THEN 3 ELSE 4 END
	`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []MDMComplianceResult{}
	for rows.Next() {
		var r MDMComplianceResult
		if rows.Scan(&r.RuleID, &r.RuleType, &r.Status, &r.ActualValue, &r.Severity, &r.CheckedAt) == nil {
			out = append(out, r)
		}
	}
	return out, nil
}

// GetComplianceSummary returns fleet-level compliance stats for a tenant.
func GetComplianceSummary(tenantID int) map[string]any {
	var compliant, nonCompliant, unknown, total int
	database.RDB().QueryRow(`
		SELECT
			COUNT(*) FILTER (WHERE compliance_status = 'compliant'),
			COUNT(*) FILTER (WHERE compliance_status = 'non_compliant'),
			COUNT(*) FILTER (WHERE compliance_status = 'unknown'),
			COUNT(*)
		FROM mdm_devices
		WHERE tenant_id = $1 AND status = 'enrolled'
	`, tenantID).Scan(&compliant, &nonCompliant, &unknown, &total)

	// Most common failure reasons.
	type failRow struct {
		RuleType string `json:"rule_type"`
		Count    int    `json:"count"`
	}
	failRows, _ := database.RDB().Query(`
		SELECT r.rule_type, COUNT(*) AS cnt
		FROM mdm_compliance_results cr
		JOIN mdm_policy_rules r ON r.id = cr.rule_id
		JOIN mdm_devices d ON d.id = cr.device_id AND d.tenant_id = $1
		WHERE cr.status = 'fail'
		GROUP BY r.rule_type
		ORDER BY cnt DESC
		LIMIT 10
	`, tenantID)
	topFailures := []failRow{}
	if failRows != nil {
		defer failRows.Close()
		for failRows.Next() {
			var fr failRow
			if failRows.Scan(&fr.RuleType, &fr.Count) == nil {
				topFailures = append(topFailures, fr)
			}
		}
	}

	// Per-platform breakdown.
	platRows, _ := database.RDB().Query(`
		SELECT platform,
		       COUNT(*) FILTER (WHERE compliance_status = 'compliant')     AS pass,
		       COUNT(*) FILTER (WHERE compliance_status = 'non_compliant') AS fail,
		       COUNT(*) AS total
		FROM mdm_devices
		WHERE tenant_id=$1 AND status='enrolled'
		GROUP BY platform
	`, tenantID)
	type platRow struct {
		Platform string `json:"platform"`
		Pass     int    `json:"pass"`
		Fail     int    `json:"fail"`
		Total    int    `json:"total"`
	}
	byPlatform := []platRow{}
	if platRows != nil {
		defer platRows.Close()
		for platRows.Next() {
			var pr platRow
			if platRows.Scan(&pr.Platform, &pr.Pass, &pr.Fail, &pr.Total) == nil {
				byPlatform = append(byPlatform, pr)
			}
		}
	}

	rate := 0.0
	if total > 0 {
		rate = float64(compliant) / float64(total) * 100
	}
	return map[string]any{
		"total":           total,
		"compliant":       compliant,
		"non_compliant":   nonCompliant,
		"unknown":         unknown,
		"compliance_rate": rate,
		"top_failures":    topFailures,
		"by_platform":     byPlatform,
	}
}

// ── Command queue ─────────────────────────────────────────────────────────────

// QueueCommand creates a pending MDM command for a device.
func QueueCommand(tenantID, deviceID, userID int, commandType string, payload map[string]any) (int, error) {
	payloadJSON, _ := json.Marshal(payload)
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO mdm_commands
			(tenant_id, device_id, command_type, payload, queued_by)
		VALUES ($1,$2,$3,$4,$5)
		RETURNING id
	`, tenantID, deviceID, commandType, payloadJSON, nullableUserID(userID)).Scan(&id)
	log.Printf("[MDM] command queued: type=%s device=%d tenant=%d", commandType, deviceID, tenantID)
	return id, err
}

// ListCommands returns commands for a device, newest first.
func ListCommands(deviceID, tenantID, limit int) ([]MDMCommand, error) {
	var ownerCount int
	database.RDB().QueryRow(
		`SELECT COUNT(*) FROM mdm_devices WHERE id=$1 AND tenant_id=$2`,
		deviceID, tenantID,
	).Scan(&ownerCount)
	if ownerCount == 0 {
		return nil, fmt.Errorf("device not found")
	}

	rows, err := database.RDB().Query(`
		SELECT id, tenant_id, device_id, command_type, payload, status,
		       queued_by, queued_at, sent_at, acknowledged_at, error_msg
		FROM mdm_commands
		WHERE device_id=$1
		ORDER BY queued_at DESC
		LIMIT $2
	`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []MDMCommand{}
	for rows.Next() {
		var c MDMCommand
		payloadJSON := []byte{}
		if rows.Scan(&c.ID, &c.TenantID, &c.DeviceID, &c.CommandType, &payloadJSON,
			&c.Status, &c.QueuedBy, &c.QueuedAt, &c.SentAt, &c.AcknowledgedAt, &c.ErrorMsg) == nil {
			json.Unmarshal(payloadJSON, &c.Payload)
			out = append(out, c)
		}
	}
	return out, nil
}

// AcknowledgeCommand marks a command as acknowledged (device confirmed receipt).
func AcknowledgeCommand(commandID int, success bool, errMsg string) error {
	status := "acknowledged"
	if !success {
		status = "failed"
	}
	_, err := database.DB.Exec(`
		UPDATE mdm_commands
		SET status=$1, acknowledged_at=NOW(), error_msg=$2
		WHERE id=$3
	`, status, errMsg, commandID)
	return err
}

// DeliverPendingCommands marks pending commands as "sent" and invokes the
// push delivery stub. Real APNS/FCM integration replaces deliverViaPush().
func DeliverPendingCommands() {
	rows, err := database.DB.Query(`
		SELECT c.id, c.command_type, c.payload, d.push_token, d.platform
		FROM mdm_commands c
		JOIN mdm_devices d ON d.id = c.device_id
		WHERE c.status = 'pending' AND d.push_token != '' AND d.status = 'enrolled'
		ORDER BY c.queued_at
		LIMIT 100
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int
		var commandType, pushToken, platform string
		payloadJSON := []byte{}
		if rows.Scan(&id, &commandType, &payloadJSON, &pushToken, &platform) != nil {
			continue
		}
		if err := deliverViaPush(platform, pushToken, commandType, payloadJSON); err != nil {
			database.DB.Exec(`UPDATE mdm_commands SET error_msg=$1 WHERE id=$2`, err.Error(), id)
			continue
		}
		database.DB.Exec(
			`UPDATE mdm_commands SET status='sent', sent_at=NOW() WHERE id=$1`, id,
		)
	}
}

// deliverViaPush is the push delivery stub. Wire APNS/FCM here.
func deliverViaPush(platform, pushToken, commandType string, payload []byte) error {
	// TODO: APNS for ios/macos, FCM for android, WNS for windows.
	// Until credentials are configured, log and treat as delivered.
	log.Printf("[MDM] push stub: platform=%s cmd=%s token=%s...",
		platform, commandType, pushToken[:min(8, len(pushToken))])
	return nil
}

// ── Profile management ────────────────────────────────────────────────────────

func CreateProfile(p MDMProfile) (int, error) {
	var id int
	err := database.DB.QueryRow(`
		INSERT INTO mdm_profiles
			(tenant_id, name, description, platform, profile_type, content, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING id
	`, p.TenantID, p.Name, p.Description, p.Platform, p.ProfileType, p.Content, p.IsActive,
	).Scan(&id)
	return id, err
}

func ListProfiles(tenantID int) ([]MDMProfile, error) {
	rows, err := database.RDB().Query(`
		SELECT id, tenant_id, name, description, platform, profile_type, is_active, created_at, updated_at
		FROM mdm_profiles
		WHERE tenant_id=$1
		ORDER BY name
	`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []MDMProfile{}
	for rows.Next() {
		var p MDMProfile
		if rows.Scan(&p.ID, &p.TenantID, &p.Name, &p.Description,
			&p.Platform, &p.ProfileType, &p.IsActive, &p.CreatedAt, &p.UpdatedAt) == nil {
			out = append(out, p)
		}
	}
	return out, nil
}

// DeployProfileToDevices queues push_profile commands for all enrolled devices
// on the matching platform. Returns the number of devices targeted.
func DeployProfileToDevices(profileID, tenantID, userID int) (int, error) {
	var profile MDMProfile
	err := database.RDB().QueryRow(`
		SELECT id, tenant_id, platform, name FROM mdm_profiles WHERE id=$1 AND tenant_id=$2`,
		profileID, tenantID,
	).Scan(&profile.ID, &profile.TenantID, &profile.Platform, &profile.Name)
	if err != nil {
		return 0, fmt.Errorf("profile not found")
	}

	q := `SELECT id FROM mdm_devices WHERE tenant_id=$1 AND status='enrolled'`
	args := []any{tenantID}
	if profile.Platform != "all" {
		q += ` AND platform=$2`
		args = append(args, profile.Platform)
	}
	rows, err := database.DB.Query(q, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	count := 0
	for rows.Next() {
		var deviceID int
		if rows.Scan(&deviceID) != nil {
			continue
		}
		// Upsert deployment record.
		database.DB.Exec(`
			INSERT INTO mdm_profile_deployments (profile_id, device_id, status)
			VALUES ($1,$2,'pending')
			ON CONFLICT (profile_id, device_id) DO UPDATE SET status='pending', deployed_at=NOW()
		`, profileID, deviceID)
		// Queue push command.
		QueueCommand(tenantID, deviceID, userID, "push_profile",
			map[string]any{"profile_id": profileID, "profile_name": profile.Name})
		count++
	}
	return count, nil
}

// ── Scheduler ─────────────────────────────────────────────────────────────────

// StartMDMScheduler runs compliance evaluation every 30 minutes and
// command delivery every 2 minutes.
func StartMDMScheduler() {
	go func() {
		time.Sleep(2 * time.Minute) // let DB settle after startup

		// Compliance: every 30 minutes.
		go func() {
			for {
				tenants, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active=true`)
				if err == nil {
					for tenants.Next() {
						var tid int
						if tenants.Scan(&tid) == nil {
							RunComplianceForTenant(tid)
						}
					}
					tenants.Close()
				}
				time.Sleep(30 * time.Minute)
			}
		}()

		// Command delivery: every 2 minutes.
		go func() {
			for {
				DeliverPendingCommands()
				time.Sleep(2 * time.Minute)
			}
		}()
	}()
	log.Println("[MDM] scheduler started (compliance=30m, delivery=2m)")
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func nullableUserID(id int) any {
	if id == 0 {
		return nil
	}
	return id
}
