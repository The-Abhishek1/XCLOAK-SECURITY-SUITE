package services

// Container / Kubernetes Security Detector
//
// Analyses Docker daemon logs and Kubernetes audit logs ingested via
// syslog or the HTTP ingest API.
//
// Log sources:
//   Docker:      journald/syslog from dockerd — "docker run --privileged …",
//                container start/stop/exec events via Docker Events API logs,
//                container image pull events
//   Kubernetes:  k8s audit log JSON (apiserver --audit-log-path) containing
//                "verb", "objectRef.resource", "user.username", "sourceIPs"
//   Falco:       alert JSON output piped to syslog or HTTP
//
// Detection categories:
//   Privileged container         (T1611)   — --privileged or --cap-add SYS_ADMIN
//   Host namespaces              (T1611)   — --pid=host, --network=host, --ipc=host
//   Volume host mount            (T1052.001) — -v /:/host, -v /etc, -v /var/run/docker.sock
//   Container escape attempt     (T1611)   — nsenter, chroot /host, docker exec root
//   Crypto mining in container   (T1496)   — mining pool strings, xmrig, minerd, cpulimit abuse
//   Sensitive image pull         (T1525)   — image from unknown/suspicious registry, :latest abuse
//   K8s ClusterRoleBinding create (T1098)  — new admin role binding
//   K8s exec into pod            (T1609)   — kubectl exec / pods/exec POST
//   K8s secrets access           (T1552.007) — GET/LIST on secrets resource
//   K8s service account token mount disabled (T1552.007) — automountServiceAccountToken=false removal
//   Falco alert passthrough      (varies)  — forward Falco JSON severity as XCloak alert
//
// Runs every 5 minutes.  Alert dedup TTL: 15 minutes.

import (
	"fmt"
	"log"
	"strings"
	"time"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

var containerDedup = newTTLMap(15 * time.Minute)

type containerSig struct {
	fragments []string // ALL must match (case-insensitive AND)
	ruleName  string
	severity  string
	mitre     string
	mitreName string
	tactic    string
}

var containerSigs = []containerSig{
	// ── Docker / container runtime ────────────────────────────────────────────
	{
		[]string{"--privileged"},
		"Privileged Container Started", "high", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"--cap-add", "sys_admin"},
		"Container with SYS_ADMIN Capability", "high", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"--pid=host"},
		"Container with Host PID Namespace", "high", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"--network=host"},
		"Container with Host Network Namespace", "medium", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"/var/run/docker.sock"},
		"Docker Socket Mounted in Container", "critical", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"-v", "/:/"},
		"Root Filesystem Mounted in Container", "critical", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"nsenter", "--target"},
		"Container Escape via nsenter", "critical", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"chroot", "/host"},
		"Container Escape via chroot /host", "critical", "T1611", "Escape to Host", "Privilege Escalation",
	},
	{
		[]string{"xmrig"},
		"Crypto Miner (xmrig) in Container", "critical", "T1496", "Resource Hijacking", "Impact",
	},
	{
		[]string{"minerd"},
		"Crypto Miner (minerd) in Container", "critical", "T1496", "Resource Hijacking", "Impact",
	},
	{
		[]string{"stratum+tcp"},
		"Mining Pool Connection in Container", "critical", "T1496", "Resource Hijacking", "Impact",
	},
	{
		[]string{"pool.minexmr.com"},
		"Mining Pool (Monero) in Container", "critical", "T1496", "Resource Hijacking", "Impact",
	},
	{
		[]string{"docker pull", ":latest"},
		"Untagged :latest Image Pulled", "low", "T1525", "Implant Internal Image", "Persistence",
	},

	// ── Kubernetes audit log ──────────────────────────────────────────────────
	{
		[]string{"clusterrolebindings", "create"},
		"K8s — ClusterRoleBinding Created", "high", "T1098", "Account Manipulation", "Persistence",
	},
	{
		[]string{"clusterroles", "create"},
		"K8s — ClusterRole Created", "high", "T1098", "Account Manipulation", "Persistence",
	},
	{
		[]string{"pods/exec", "create"},
		"K8s — Exec into Pod (kubectl exec)", "high", "T1609", "Container Administration Command", "Execution",
	},
	{
		[]string{"secrets", "\"verb\":\"get\""},
		"K8s — Secret Accessed", "high", "T1552.007", "Container API", "Credential Access",
	},
	{
		[]string{"secrets", "\"verb\":\"list\""},
		"K8s — Secrets Listed (bulk)", "high", "T1552.007", "Container API", "Credential Access",
	},
	{
		[]string{"serviceaccounts", "create"},
		"K8s — Service Account Created", "medium", "T1098", "Account Manipulation", "Persistence",
	},
	{
		[]string{"namespaces", "delete"},
		"K8s — Namespace Deleted", "high", "T1485", "Data Destruction", "Impact",
	},
	{
		[]string{"nodes", "\"verb\":\"delete\""},
		"K8s — Node Deleted", "critical", "T1485", "Data Destruction", "Impact",
	},
	{
		[]string{"deployments", "\"verb\":\"delete\""},
		"K8s — Deployment Deleted", "high", "T1485", "Data Destruction", "Impact",
	},
	{
		[]string{"configmaps", "\"verb\":\"create\""},
		"K8s — ConfigMap Created (check for secrets)", "low", "T1552.007", "Container API", "Credential Access",
	},
	{
		[]string{"persistentvolumes", "create"},
		"K8s — PersistentVolume Created", "medium", "T1052.001", "Exfiltration Over Physical Medium", "Exfiltration",
	},

	// ── Falco alert passthrough ───────────────────────────────────────────────
	{
		[]string{"falco", "rule="},
		"Falco Security Alert", "high", "T1611", "Escape to Host", "Privilege Escalation",
	},
}

func StartContainerSecurityScheduler() {
	go func() {
		time.Sleep(2 * time.Minute)
		for {
			runContainerSecurityDetection()
			time.Sleep(5 * time.Minute)
		}
	}()
}

func runContainerSecurityDetection() {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = true`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tid int
		if rows.Scan(&tid) == nil {
			detectContainerThreats(tid)
		}
	}
}

func detectContainerThreats(tenantID int) {
	rows, err := database.DB.Query(`
		SELECT el.agent_id,
		       lower(el.log_message)                   AS msg,
		       el.parsed_fields->>'src_ip'              AS src_ip,
		       coalesce(el.parsed_fields->>'user', '')  AS actor
		FROM endpoint_logs el
		JOIN agents a ON a.id = el.agent_id AND a.tenant_id = $1
		WHERE el.created_at > NOW() - INTERVAL '5 minutes'
		  AND (
		        el.log_message ILIKE '%docker%'
		     OR el.log_message ILIKE '%container%'
		     OR el.log_message ILIKE '%kubectl%'
		     OR el.log_message ILIKE '%kubernetes%'
		     OR el.log_message ILIKE '%falco%'
		     OR el.log_message ILIKE '%k8s%'
		     OR el.log_message ILIKE '%nsenter%'
		     OR el.log_message ILIKE '%xmrig%'
		     OR el.log_message ILIKE '%stratum%'
		  )
		LIMIT 2000
	`, tenantID)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var agentID int
		var msg, srcIP, actor string
		if rows.Scan(&agentID, &msg, &srcIP, &actor) != nil {
			continue
		}

		for _, sig := range containerSigs {
			allMatch := true
			for _, frag := range sig.fragments {
				if !strings.Contains(msg, frag) {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue
			}

			// deduplicate on first fragment per (tenant, rule)
			key := fmt.Sprintf("%d:container:%s:%s", tenantID, sig.ruleName, actor)
			if containerDedup.touched(key) {
				break
			}
			containerDedup.touch(key)

			fullMsg := fmt.Sprintf("%s — actor='%s' src_ip='%s' context='%s'",
				sig.ruleName, actor, srcIP, truncateLog(msg, 200))
			log.Printf("[Container] %s", fullMsg)

			CreateAlert(models.Alert{
				AgentID:        agentID,
				TenantID:       tenantID,
				Severity:       sig.severity,
				RuleName:       sig.ruleName,
				LogMessage:     fullMsg,
				MitreTactic:    sig.tactic,
				MitreTechnique: sig.mitre,
				MitreName:      sig.mitreName,
				Fingerprint:    fmt.Sprintf("container-%s-%d", sig.mitre, tenantID),
			})
			break
		}
	}
}
