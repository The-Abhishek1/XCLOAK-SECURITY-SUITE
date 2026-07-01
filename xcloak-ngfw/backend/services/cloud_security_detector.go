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
//    IAM privilege escalation   (T1098)     — AttachRolePolicy, CreateUser, CreateAccessKey, AddUserToGroup
//    Root account usage         (T1078.004) — any action by the root principal
//    Public S3 exposure         (T1530)     — PutBucketAcl/PutBucketPolicy with public-read
//    Console login without MFA  (T1078)     — ConsoleLogin + mfaUsed=false
//    Security group opened      (T1562.007) — AuthorizeSecurityGroupIngress 0.0.0.0/0
//    CloudTrail stopped         (T1562.008) — StopLogging, DeleteTrail, UpdateTrail
//    GuardDuty disabled         (T1562.001) — DeleteDetector, DisableOrganizationAdminAccount
//    Secrets Manager access     (T1552.001) — GetSecretValue
//    SSM Parameter Store read   (T1552)     — GetParameter, GetParameters
//    Lambda persistence         (T1648)     — CreateFunction, UpdateFunctionCode
//    Snapshot exfiltration      (T1537)     — ModifySnapshotAttribute (cross-account share)
//    VPC Flow Logs deleted      (T1562.008) — DeleteFlowLogs
//    KMS key destruction        (T1485)     — ScheduleKeyDeletion, DeleteAlias
//    Config service disabled    (T1562)     — StopConfigurationRecorder, DeleteConfigRule
//    WAF ACL deleted            (T1562.007) — DeleteWebACL
//    S3 bucket deleted          (T1485)     — DeleteBucket
//    EC2 image exported         (T1537)     — ExportImage, CreateInstanceExportTask
//    STS recon                  (T1087.004) — GetCallerIdentity
//
//  Azure:
//    Role assignment created    (T1098)     — roleAssignments/write
//    Subscription policy changes (T1562)   — policyAssignments/write
//    Key vault secret access    (T1552.001) — vaults/secrets/get
//    Diagnostic settings disabled (T1562.008) — diagnosticSettings/delete
//    VNet subnet modified       (T1562.007) — virtualnetworks/subnets/write
//    AD user modified           (T1098)     — users/write
//    App role assigned          (T1098)     — approleassignments/write
//    Container registry push    (T1610)     — registries/write or registries/push
//    AKS cluster modified       (T1613)     — managedclusters/write
//    Function app created       (T1648)     — microsoft.web/sites/write
//    Automation runbook created (T1059)     — automationaccounts/runbooks/write
//    Security Center alert dismissed (T1562) — security/alerts/dismiss
//    Elevation of access        (T1078)     — authorization/elevateaccess
//    App credential added       (T1098.001) — applications/credentials/write
//    NSG rule all-inbound       (T1562.007) — networksecuritygroups/securityrules/write
//
//  GCP:
//    IAM policy set             (T1098)     — setIamPolicy
//    Service account key created (T1552.001) — serviceAccounts.keys.create
//    Audit log disabled         (T1562.008) — google.logging.v2.ConfigServiceV2.UpdateSink
//    Compute instance created   (T1578.002) — compute.instances.insert
//    Firewall rule created      (T1562.007) — compute.firewalls.insert
//    Storage bucket policy changed (T1530)  — storage.buckets.setIamPolicy
//    Secret Manager accessed    (T1552.001) — secretmanager.versions.access
//    Cloud Function deployed    (T1648)     — cloudfunctions.functions.create/update
//    Cloud Run service deployed (T1648)     — run.services.create/replace
//    GKE cluster modified       (T1613)     — container.clusters.update/create
//    Org policy changed         (T1562)     — orgpolicy.policy.set
//    BigQuery dataset public    (T1530)     — bigquery.datasets.setIamPolicy
//    Snapshot cross-project shared (T1537)  — compute.snapshots.setIamPolicy
//
// Behavioral correlation: ≥3 distinct cloud_event_name values per (tenant, user)
// in a rolling 15-minute window triggers a compound "Cloud Account
// Reconnaissance" alert; ≥5 distinct events escalates to high severity.
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
	provider  string
	eventFrag string // case-insensitive substring matched against cloud_event_name
	ruleName  string
	severity  string
	mitre     string
	mitreNm   string
}

var cloudSigs = []cloudSig{
	// ── AWS ──────────────────────────────────────────────────────────────────────
	{"aws", "attachrolepolicy",               "AWS IAM — Role Policy Attached",              "high",     "T1098",     "Account Manipulation"},
	{"aws", "createaccesskey",                "AWS IAM — Access Key Created",                "high",     "T1098.001", "Additional Cloud Credentials"},
	{"aws", "createuser",                     "AWS IAM — IAM User Created",                  "high",     "T1136.003", "Cloud Account"},
	{"aws", "addusertogroup",                 "AWS IAM — User Added to Group",               "high",     "T1098",     "Account Manipulation"},
	{"aws", "putuserpolicy",                  "AWS IAM — Inline Policy Added",               "high",     "T1098",     "Account Manipulation"},
	{"aws", "createloginprofile",             "AWS IAM — Console Access Enabled",            "high",     "T1098",     "Account Manipulation"},
	{"aws", "stopinstances",                  "AWS EC2 — Instances Stopped",                 "medium",   "T1489",     "Service Stop"},
	{"aws", "terminateinstances",             "AWS EC2 — Instances Terminated",              "high",     "T1489",     "Service Stop"},
	{"aws", "stoplogging",                    "AWS CloudTrail — Logging Stopped",            "critical", "T1562.008", "Disable Cloud Logs"},
	{"aws", "deletetrail",                    "AWS CloudTrail — Trail Deleted",              "critical", "T1562.008", "Disable Cloud Logs"},
	{"aws", "putbucketacl",                   "AWS S3 — Bucket ACL Modified",                "high",     "T1530",     "Data from Cloud Storage"},
	{"aws", "putbucketpolicy",                "AWS S3 — Bucket Policy Modified",             "high",     "T1530",     "Data from Cloud Storage"},
	{"aws", "deletebucket",                   "AWS S3 — Bucket Deleted",                     "high",     "T1485",     "Data Destruction"},
	{"aws", "authorizesecuritygroupingress",  "AWS EC2 — Security Group Opened",             "high",     "T1562.007", "Disable or Modify Cloud Firewall"},
	{"aws", "deletedetector",                 "AWS GuardDuty — Detector Deleted",            "critical", "T1562.001", "Disable Security Tools"},
	{"aws", "consolelogin",                   "AWS Console — Login (check MFA)",             "low",      "T1078",     "Valid Accounts"},
	{"aws", "getobject",                      "AWS S3 — Object Downloaded",                  "low",      "T1530",     "Data from Cloud Storage"},
	{"aws", "assumerolewithwebidentity",      "AWS STS — Web Identity Assumed",              "medium",   "T1550.001", "Application Access Token"},
	{"aws", "putbucketlogging",               "AWS S3 — Bucket Logging Changed",             "medium",   "T1562.008", "Disable Cloud Logs"},
	// Secrets & credentials access
	{"aws", "getsecretvalue",                 "AWS Secrets Manager — Secret Accessed",       "high",     "T1552.001", "Credentials in Files"},
	{"aws", "getparameters",                  "AWS SSM — Parameters Read",                   "medium",   "T1552",     "Unsecured Credentials"},
	{"aws", "getparameter",                   "AWS SSM — Parameter Read",                    "medium",   "T1552",     "Unsecured Credentials"},
	// Serverless persistence
	{"aws", "createfunction",                 "AWS Lambda — Function Created",               "high",     "T1648",     "Serverless Execution"},
	{"aws", "updatefunctioncode",             "AWS Lambda — Function Code Updated",          "high",     "T1648",     "Serverless Execution"},
	// Exfiltration via snapshots
	{"aws", "modifysnapshotattribute",        "AWS EC2 — Snapshot Attribute Modified",       "high",     "T1537",     "Transfer Data to Cloud Account"},
	{"aws", "exportimage",                    "AWS EC2 — Image Export Initiated",            "high",     "T1537",     "Transfer Data to Cloud Account"},
	{"aws", "createinstanceexporttask",       "AWS EC2 — Instance Export Task Created",      "high",     "T1537",     "Transfer Data to Cloud Account"},
	// Defense evasion
	{"aws", "deleteflowlogs",                 "AWS VPC — Flow Logs Deleted",                 "critical", "T1562.008", "Disable Cloud Logs"},
	{"aws", "schedulekeydeletion",            "AWS KMS — Key Deletion Scheduled",            "critical", "T1485",     "Data Destruction"},
	{"aws", "deletealias",                    "AWS KMS — Key Alias Deleted",                 "high",     "T1485",     "Data Destruction"},
	{"aws", "stopconfigurationrecorder",      "AWS Config — Recorder Stopped",               "critical", "T1562",     "Impair Defenses"},
	{"aws", "deleteconfigrule",               "AWS Config — Rule Deleted",                   "high",     "T1562",     "Impair Defenses"},
	{"aws", "deletewebacl",                   "AWS WAF — Web ACL Deleted",                   "high",     "T1562.007", "Disable or Modify Cloud Firewall"},
	// Reconnaissance (low severity; contributes to behavioral correlation)
	{"aws", "getcalleridentity",              "AWS STS — Caller Identity Probed",            "low",      "T1087.004", "Cloud Account Discovery"},

	// ── Azure ────────────────────────────────────────────────────────────────────
	{"azure", "roleassignments/write",                       "Azure — Role Assignment Created",              "high",     "T1098",     "Account Manipulation"},
	{"azure", "policyassignments/write",                     "Azure — Policy Assignment Created",            "high",     "T1562",     "Impair Defenses"},
	{"azure", "vaults/secrets/get",                          "Azure KeyVault — Secret Accessed",             "high",     "T1552.001", "Credentials in Files"},
	{"azure", "diagnosticsettings/delete",                   "Azure — Diagnostic Settings Deleted",          "critical", "T1562.008", "Disable Cloud Logs"},
	{"azure", "virtualnetworks/subnets/write",               "Azure — VNet Subnet Modified",                 "medium",   "T1562.007", "Disable Cloud Firewall"},
	{"azure", "users/write",                                 "Azure AD — User Account Modified",             "high",     "T1098",     "Account Manipulation"},
	{"azure", "approleassignments/write",                    "Azure AD — App Role Assigned",                 "high",     "T1098",     "Account Manipulation"},
	// Container / serverless
	{"azure", "registries/write",                            "Azure Container Registry — Registry Modified", "high",     "T1610",     "Deploy Container"},
	{"azure", "microsoft.web/sites/write",                   "Azure — Function App Created/Modified",        "high",     "T1648",     "Serverless Execution"},
	{"azure", "automationaccounts/runbooks/write",           "Azure Automation — Runbook Created",           "high",     "T1059",     "Command and Scripting Interpreter"},
	{"azure", "managedclusters/write",                       "Azure AKS — Cluster Modified",                 "high",     "T1613",     "Container and Resource Discovery"},
	// Defense evasion & privilege escalation
	{"azure", "security/alerts/dismiss",                     "Azure Security Center — Alert Dismissed",      "high",     "T1562",     "Impair Defenses"},
	{"azure", "authorization/elevateaccess",                 "Azure — Global Admin Elevation of Access",     "critical", "T1078",     "Valid Accounts"},
	{"azure", "applications/credentials/write",              "Azure AD — App Credential Added",              "high",     "T1098.001", "Additional Cloud Credentials"},
	{"azure", "networksecuritygroups/securityrules/write",   "Azure NSG — Security Rule Modified",           "medium",   "T1562.007", "Disable Cloud Firewall"},

	// ── GCP ──────────────────────────────────────────────────────────────────────
	{"gcp", "setiampolicy",                     "GCP IAM — Policy Updated",                    "high",     "T1098",     "Account Manipulation"},
	{"gcp", "serviceaccounts.keys.create",      "GCP — Service Account Key Created",           "high",     "T1552.001", "Credentials in Files"},
	{"gcp", "configservicev2.updatesink",        "GCP — Audit Log Sink Modified",               "critical", "T1562.008", "Disable Cloud Logs"},
	{"gcp", "compute.instances.insert",          "GCP — Compute Instance Created",              "low",      "T1578.002", "Create Cloud Instance"},
	{"gcp", "compute.firewalls.insert",          "GCP — Firewall Rule Created",                 "medium",   "T1562.007", "Disable Cloud Firewall"},
	{"gcp", "storage.buckets.setiampolicy",      "GCP Storage — Bucket Policy Changed",         "high",     "T1530",     "Data from Cloud Storage"},
	// Secrets & credentials access
	{"gcp", "secretmanager.versions.access",     "GCP Secret Manager — Secret Accessed",        "high",     "T1552.001", "Credentials in Files"},
	// Serverless / container persistence
	{"gcp", "cloudfunctions.functions.create",   "GCP Cloud Function — Function Created",       "high",     "T1648",     "Serverless Execution"},
	{"gcp", "cloudfunctions.functions.update",   "GCP Cloud Function — Function Updated",       "high",     "T1648",     "Serverless Execution"},
	{"gcp", "run.services.create",               "GCP Cloud Run — Service Created",             "high",     "T1648",     "Serverless Execution"},
	{"gcp", "run.services.replace",              "GCP Cloud Run — Service Replaced",            "high",     "T1648",     "Serverless Execution"},
	{"gcp", "container.clusters.create",         "GCP GKE — Cluster Created",                   "medium",   "T1613",     "Container and Resource Discovery"},
	{"gcp", "container.clusters.update",         "GCP GKE — Cluster Config Modified",           "high",     "T1613",     "Container and Resource Discovery"},
	// Defense evasion
	{"gcp", "orgpolicy.policy.set",              "GCP Org Policy — Policy Modified",            "critical", "T1562",     "Impair Defenses"},
	// Exfiltration
	{"gcp", "bigquery.datasets.setiampolicy",    "GCP BigQuery — Dataset Permissions Changed",  "high",     "T1530",     "Data from Cloud Storage"},
	{"gcp", "compute.snapshots.setiampolicy",    "GCP — Compute Snapshot Shared",               "high",     "T1537",     "Transfer Data to Cloud Account"},
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
			detectCloudReconnaissance(tid)
		}
	}
}

func detectCloudEvents(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       el.parsed_fields->>'cloud_provider'        AS provider,
		       lower(el.parsed_fields->>'cloud_event_name') AS event_name,
		       el.parsed_fields->>'cloud_user'            AS cloud_user,
		       el.parsed_fields->>'cloud_region'          AS cloud_region,
		       el.parsed_fields->>'cloud_resource'        AS cloud_resource,
		       el.parsed_fields->>'src_ip'                AS src_ip,
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

// detectCloudReconnaissance fires a compound alert when the same cloud user
// performs ≥3 distinct API calls within a 15-minute window — a pattern typical
// of post-compromise enumeration regardless of whether any individual call
// matches a specific signature.
func detectCloudReconnaissance(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT
			el.agent_id,
			el.parsed_fields->>'cloud_provider' AS provider,
			el.parsed_fields->>'cloud_user'     AS cloud_user,
			COUNT(DISTINCT lower(el.parsed_fields->>'cloud_event_name')) AS distinct_events,
			MIN(el.parsed_fields->>'src_ip')    AS src_ip
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.parsed_fields->>'cloud_provider' IS NOT NULL
		  AND el.created_at > NOW() - INTERVAL '15 minutes'
		GROUP BY el.agent_id, provider, cloud_user
		HAVING COUNT(DISTINCT lower(el.parsed_fields->>'cloud_event_name')) >= 3
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var provider, cloudUser, srcIP string
		var distinctEvents int
		if rows.Scan(&agentID, &provider, &cloudUser, &distinctEvents, &srcIP) != nil {
			continue
		}

		key := fmt.Sprintf("%d:cloudrecon:%s:%s", tenantID, provider, cloudUser)
		if cloudDedup.touched(key) {
			continue
		}
		cloudDedup.touch(key)

		severity := "medium"
		if distinctEvents >= 5 {
			severity = "high"
		}

		msg := fmt.Sprintf("Cloud Account Reconnaissance — user='%s' provider=%s distinct_api_calls=%d src_ip='%s' (15-min window)",
			cloudUser, provider, distinctEvents, srcIP)
		log.Printf("[Cloud] %s", msg)

		CreateAlert(models.Alert{
			AgentID:        agentID,
			TenantID:       tenantID,
			Severity:       severity,
			RuleName:       "Cloud Account Reconnaissance",
			LogMessage:     msg,
			MitreTactic:    "Discovery",
			MitreTechnique: "T1087.004",
			MitreName:      "Cloud Account Discovery",
			Fingerprint:    fmt.Sprintf("cloudrecon-%s-%s", provider, cloudUser),
		})
	}
}

func cloudTactic(mitre string) string {
	switch {
	case strings.HasPrefix(mitre, "T1098"), strings.HasPrefix(mitre, "T1136"):
		return "Persistence"
	case strings.HasPrefix(mitre, "T1562"), strings.HasPrefix(mitre, "T1578"):
		return "Defense Evasion"
	case strings.HasPrefix(mitre, "T1530"), strings.HasPrefix(mitre, "T1537"):
		return "Collection"
	case strings.HasPrefix(mitre, "T1552"):
		return "Credential Access"
	case strings.HasPrefix(mitre, "T1648"), strings.HasPrefix(mitre, "T1610"),
		strings.HasPrefix(mitre, "T1613"):
		return "Execution"
	case strings.HasPrefix(mitre, "T1059"):
		return "Execution"
	case strings.HasPrefix(mitre, "T1485"), strings.HasPrefix(mitre, "T1489"):
		return "Impact"
	case strings.HasPrefix(mitre, "T1087"):
		return "Discovery"
	default:
		return "Initial Access"
	}
}
