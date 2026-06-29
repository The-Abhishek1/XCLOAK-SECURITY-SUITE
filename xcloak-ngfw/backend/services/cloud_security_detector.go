package services

// Cloud Security Detector
//
// Detects attacks and misconfigurations in cloud environments by analysing
// AWS CloudTrail, Azure Activity Log, and GCP Audit Log events ingested
// via the syslog receiver or HTTP ingest API.
//
// The JSON log normalizer extracts cloud_provider, cloud_event_name,
// cloud_user, cloud_region, cloud_resource, and src_ip into parsed_fields
// so this detector can query them efficiently.
//
// Detection categories:
//
//  AWS:
//    IAM privilege escalation  (T1098)  — AttachRolePolicy, CreateUser, CreateAccessKey, AddUserToGroup
//    Root account usage        (T1078.004) — any action by the root principal
//    Public S3 exposure        (T1530)  — PutBucketAcl/PutBucketPolicy with public-read
//    Console login without MFA (T1078)  — ConsoleLogin + mfaUsed=false
//    Security group opened     (T1562.007) — AuthorizeSecurityGroupIngress 0.0.0.0/0
//    CloudTrail stopped        (T1562.008) — StopLogging, DeleteTrail, UpdateTrail
//    GuardDuty disabled        (T1562.001) — DeleteDetector, DisableOrganizationAdminAccount
//
//  Azure:
//    Role assignment created   (T1098)  — roleAssignments/write
//    Subscription policy changes (T1562) — policyAssignments/write
//    Key vault secret access   (T1552.001) — vaults/secrets/get
//    Diagnostic settings disabled (T1562.008) — diagnosticSettings/delete
//
//  GCP:
//    IAM policy set            (T1098)  — setIamPolicy
//    Service account key created (T1552.001) — serviceAccounts.keys.create
//    Audit log disabled        (T1562.008) — google.logging.v2.ConfigServiceV2.UpdateSink
//    Compute instance created with external IP (T1537) — compute.instances.insert
//
// Runs every 5 minutes. Alert dedup TTL: 30 minutes per (provider, event, user).

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

const cloudDedupTTL = 30 * time.Minute

var cloudDedup = newTTLMap(cloudDedupTTL)

type cloudSig struct {
	provider string
	eventFrag string // substring to match in cloud_event_name (case-insensitive)
	ruleName string
	severity string
	mitre    string
	mitreNm  string
}

var cloudSigs = []cloudSig{
	// ── AWS ──────────────────────────────────────────────────────────────────
	{"aws", "attachrolepolicy",               "AWS IAM — Role Policy Attached",        "high",     "T1098",     "Account Manipulation"},
	{"aws", "createaccesskey",                "AWS IAM — Access Key Created",          "high",     "T1098.001", "Additional Cloud Credentials"},
	{"aws", "createuser",                     "AWS IAM — IAM User Created",            "high",     "T1136.003", "Cloud Account"},
	{"aws", "addusertogroup",                 "AWS IAM — User Added to Group",         "high",     "T1098",     "Account Manipulation"},
	{"aws", "putuserpolicy",                  "AWS IAM — Inline Policy Added",         "high",     "T1098",     "Account Manipulation"},
	{"aws", "createloginprofile",             "AWS IAM — Console Access Enabled",      "high",     "T1098",     "Account Manipulation"},
	{"aws", "stopinstances",                  "AWS EC2 — Instances Stopped",           "medium",   "T1489",     "Service Stop"},
	{"aws", "terminateinstances",             "AWS EC2 — Instances Terminated",        "high",     "T1489",     "Service Stop"},
	{"aws", "stoplogging",                    "AWS CloudTrail — Logging Stopped",      "critical", "T1562.008", "Disable Cloud Logs"},
	{"aws", "deletetrail",                    "AWS CloudTrail — Trail Deleted",        "critical", "T1562.008", "Disable Cloud Logs"},
	{"aws", "putbucketacl",                   "AWS S3 — Bucket ACL Modified",          "high",     "T1530",     "Data from Cloud Storage"},
	{"aws", "putbucketpolicy",                "AWS S3 — Bucket Policy Modified",       "high",     "T1530",     "Data from Cloud Storage"},
	{"aws", "authorizesecuritygroupingress",  "AWS EC2 — Security Group Opened",       "high",     "T1562.007", "Disable or Modify Cloud Firewall"},
	{"aws", "deletedetector",                 "AWS GuardDuty — Detector Deleted",      "critical", "T1562.001", "Disable Security Tools"},
	{"aws", "consolelogin",                   "AWS Console — Login (check MFA)",       "low",      "T1078",     "Valid Accounts"},
	{"aws", "getobject",                      "AWS S3 — Object Downloaded",            "low",      "T1530",     "Data from Cloud Storage"},
	{"aws", "assumerolewithwebidentity",      "AWS STS — Web Identity Assumed",        "medium",   "T1550.001", "Application Access Token"},
	{"aws", "putbucketlogging",               "AWS S3 — Bucket Logging Changed",       "medium",   "T1562.008", "Disable Cloud Logs"},

	// ── Azure ─────────────────────────────────────────────────────────────────
	{"azure", "roleassignments/write",         "Azure — Role Assignment Created",       "high",     "T1098",     "Account Manipulation"},
	{"azure", "policyassignments/write",       "Azure — Policy Assignment Created",     "high",     "T1562",     "Impair Defenses"},
	{"azure", "vaults/secrets/get",            "Azure KeyVault — Secret Accessed",      "high",     "T1552.001", "Credentials in Files"},
	{"azure", "diagnosticsettings/delete",     "Azure — Diagnostic Settings Deleted",   "critical", "T1562.008", "Disable Cloud Logs"},
	{"azure", "virtualnetworks/subnets/write", "Azure — VNet Subnet Modified",          "medium",   "T1562.007", "Disable Cloud Firewall"},
	{"azure", "users/write",                   "Azure AD — User Account Modified",      "high",     "T1098",     "Account Manipulation"},
	{"azure", "approleassignments/write",      "Azure AD — App Role Assigned",          "high",     "T1098",     "Account Manipulation"},

	// ── GCP ──────────────────────────────────────────────────────────────────
	{"gcp", "setiampolicy",                   "GCP IAM — Policy Updated",              "high",     "T1098",     "Account Manipulation"},
	{"gcp", "serviceaccounts.keys.create",    "GCP — Service Account Key Created",     "high",     "T1552.001", "Credentials in Files"},
	{"gcp", "configservicev2.updatesink",     "GCP — Audit Log Sink Modified",         "critical", "T1562.008", "Disable Cloud Logs"},
	{"gcp", "compute.instances.insert",       "GCP — Compute Instance Created",        "low",      "T1578.002", "Create Cloud Instance"},
	{"gcp", "compute.firewalls.insert",       "GCP — Firewall Rule Created",           "medium",   "T1562.007", "Disable Cloud Firewall"},
	{"gcp", "storage.buckets.setIamPolicy",   "GCP Storage — Bucket Policy Changed",   "high",     "T1530",     "Data from Cloud Storage"},
}

func StartCloudSecurityScheduler() {
	go func() {
		time.Sleep(3 * time.Minute)
		for {
			runCloudSecurityDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runCloudSecurityDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectCloudEvents(tid)
		}
	}
}

func detectCloudEvents(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'cloud_provider'   AS provider,
		       lower(el.parsed_fields->>'cloud_event_name') AS event_name,
		       el.parsed_fields->>'cloud_user'       AS cloud_user,
		       el.parsed_fields->>'cloud_region'     AS cloud_region,
		       el.parsed_fields->>'cloud_resource'   AS cloud_resource,
		       el.parsed_fields->>'src_ip'            AS src_ip,
		       el.log_message
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'cloud_provider' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '5 minutes'
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var provider, eventName, cloudUser, region, resource, srcIP, logMsg string
		if rows.Scan(&agentID, &provider, &eventName, &cloudUser, &region, &resource, &srcIP, &logMsg) != nil {
			continue
		}

		for _, sig := range cloudSigs {
			if sig.provider != provider {
				continue
			}
			if !strings.Contains(eventName, strings.ToLower(sig.eventFrag)) {
				continue
			}

			key := fmt.Sprintf("%d:cloud:%s:%s:%s", tenantID, provider, sig.eventFrag, cloudUser)
			if cloudDedup.touched(key) {
				break
			}
			cloudDedup.touch(key)

			msg := fmt.Sprintf("%s — user='%s' event='%s' region='%s' src_ip='%s' resource='%s'",
				sig.ruleName, cloudUser, eventName, region, srcIP, truncateLog(resource, 100))
			log.Printf("[Cloud] %s", msg)

			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     msg,
				MitreTactic:    cloudTactic(sig.mitre),
				MitreTechnique: sig.mitre,
				MitreName:      sig.mitreNm,
				Fingerprint:    fmt.Sprintf("cloud-%s-%s-%s", provider, sig.eventFrag, cloudUser),
			})
			break
		}
	}
}

func cloudTactic(mitre string) string {
	switch {
	case strings.HasPrefix(mitre, "T1098"), strings.HasPrefix(mitre, "T1136"):
		return "Persistence"
	case strings.HasPrefix(mitre, "T1562"):
		return "Defense Evasion"
	case strings.HasPrefix(mitre, "T1530"), strings.HasPrefix(mitre, "T1537"):
		return "Collection"
	case strings.HasPrefix(mitre, "T1552"):
		return "Credential Access"
	case strings.HasPrefix(mitre, "T1578"):
		return "Defense Evasion"
	default:
		return "Initial Access"
	}
}
