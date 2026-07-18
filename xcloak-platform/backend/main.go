package main

import (
	"log"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/joho/godotenv"

	"xcloak-platform/api"
	"xcloak-platform/database"
	"xcloak-platform/logger"
	"xcloak-platform/middleware"
	"xcloak-platform/repositories"
	"xcloak-platform/routes"
	"xcloak-platform/secrets"
	"xcloak-platform/services"
)

// allowedOrigins is populated from the CORS_ALLOWED_ORIGINS env var
// (comma-separated). Falls back to the Next.js dev server origin so local
// dev keeps working without extra setup.
var allowedOrigins = map[string]bool{}

func loadAllowedOrigins() {
	raw := os.Getenv("CORS_ALLOWED_ORIGINS")
	if raw == "" {
		raw = "http://localhost:3000"
	}
	for _, o := range strings.Split(raw, ",") {
		o = strings.TrimSpace(o)
		if o != "" {
			allowedOrigins[o] = true
		}
	}
}

func main() {

	godotenv.Load()
	logger.Init()

	// Vault is optional (same BYO-infra pattern as Kafka/MinIO): Init no-ops
	// if VAULT_ADDR isn't set. Must run before database.Connect/InitRedis/
	// auth.JwtSecret's first call, since those Resolve() secrets through it.
	if err := secrets.Init(); err != nil {
		panic(err)
	}
	if err := secrets.EnsureTransitKey(services.TOTPTransitKey); err != nil {
		// Non-fatal at startup (the API should still serve everything else),
		// but every Setup2FA/Verify2FA/Disable2FA call will 500 until this is
		// fixed — encryption failing loudly beats silently storing 2FA
		// secrets in plaintext.
		slog.Warn("Vault: could not ensure TOTP transit key; 2FA endpoints will fail until resolved", "err", err)
	}

	err := database.Connect()
	if err != nil {
		panic(err)
	}

	// Read replica is optional — log a warning but don't abort startup.
	if err := database.ConnectReadReplica(); err != nil {
		slog.Warn("DB: read replica unavailable, analytics will use primary", "err", err)
	}

	// Circuit breaker monitors primary + replica health in the background.
	database.StartCircuitBreaker()

	if err := database.Migrate(); err != nil {
		panic(err)
	}

	api.InitRPETables()
	api.InitFWETables()
	api.InitSTETables()
	api.InitQETables()
	api.InitSRTables()
	api.InitFCETables()
	api.InitEXETables()
	api.InitSMETables()
	api.InitACETables()
	api.InitMDMETables()
	api.InitAIATables()
	api.InitSTTETables()
	api.InitTNETables()

	services.InitRedis()
	services.InitSaasMode()
	services.InitLicenseMode()
	go services.StartLicenseChecker()

	// ── Immutable audit log export (MinIO + Object Lock) ──────
	// Non-fatal: audit export is a compliance nice-to-have, not a hard
	// dependency for the API to serve traffic.
	if err := services.InitMinIO(); err != nil {
		slog.Warn("AuditExport: MinIO unavailable, audit export disabled", "err", err)
	} else {
		go services.StartAuditExportScheduler()
	}

	// ── Kafka event bus ──────────────────────────────────────
	services.InitKafka()
	defer services.CloseKafka()
	go services.StartIOCMatchConsumer()
	go services.StartAlertConsumer()
	go services.StartIncidentConsumer()
	go services.StartTaskConsumer()
	go services.StartAuditConsumer()
	go services.StartFIMConsumer()
	go services.StartYARAConsumer()

	// Wire WebSocket broadcaster through Redis pub/sub so all API replicas
	// deliver alerts to their own connected clients (multi-replica safety).
	// RegisterLocalBroadcastFn injects the in-process hub callback; the
	// broadcastFn registered here publishes to Redis (falls back to local
	// when Redis is unavailable).
	// ── Elasticsearch integration ─────────────────────────────────────────
	services.InitElasticsearch()
	repositories.PostSaveHook = services.IndexLogsToES

	// Wire WebSocket broadcaster through Redis pub/sub so all API replicas
	// deliver alerts to their own connected clients (multi-replica safety).
	services.RegisterLocalBroadcastFn(api.BroadcastRaw)
	services.RegisterBroadcastFn(services.PublishAlertBroadcast)
	services.StartWSBroadcastSubscriber()

	// Pre-create endpoint_logs monthly partitions (current + 3 months ahead).
	// Must run before any inserts land on a new month's first row.
	go services.StartPartitionManager()

	// Start background scheduler for recurring agent tasks.
	go services.StartScheduler()
	go services.StartHealthScheduler()
	go services.StartKEVRefreshScheduler()
	go services.StartSLAChecker()
	go services.StartScheduledReportRunner()
	services.StartUEBAAnalyzer()
	services.StartVulnPriorityScheduler()
	services.StartRiskPostureScheduler()
	services.StartHuntScheduler()
	services.StartNBAScheduler()
	services.StartActorTaggingWorker()
	services.StartClusterScheduler()
	services.StartIOCPropagation()
	services.StartITDRScheduler()
	services.StartCISScheduler()
	services.StartPlatformClassificationScheduler()
	go api.StartSessionPurger()

	go func() {
		for {
			services.WithSingletonLock("mark_offline_agents", services.MarkOfflineAgents)
			time.Sleep(30 * time.Second)
		}
	}()

	// ── Syslog receiver (UDP + TCP) ───────────────────────────────
	// Listens on SYSLOG_UDP_ADDR / SYSLOG_TCP_ADDR (default :514).
	// Non-fatal — bind errors are logged but don't stop the API.
	if os.Getenv("SYSLOG_ENABLED") != "false" {
		services.StartSyslogReceiver()
	}

	// ── C2 Beacon Detector ────────────────────────────────────────
	services.StartBeaconScheduler()

	// ── DNS Security ──────────────────────────────────────────────
	services.StartDNSSecurityScheduler()

	// ── Port Scan + Lateral Movement Detector ─────────────────────
	services.StartPortScanScheduler()

	// ── Data Exfiltration Detector ────────────────────────────────
	services.StartExfilScheduler()

	// ── TLS/JA3 Fingerprint Detector ──────────────────────────────
	services.StartJA3Scheduler()

	// ── AD/LDAP Identity Cache Refresh ────────────────────────────
	services.StartLDAPCacheRefresh()

	// ── Credential Attack Detector (brute force, spray, stuffing) ─
	services.StartCredentialAttackScheduler()

	// ── Privilege Escalation Detector ─────────────────────────────
	services.StartPrivEscScheduler()

	// ── Ransomware Behavior Detector ───────────────────────────────
	services.StartRansomwareScheduler()

	// ── Living-off-the-Land / Suspicious Process Detector ──────────
	services.StartLotLScheduler()

	// ── Impossible Travel Detector ─────────────────────────────────
	services.StartImpossibleTravelScheduler()

	// ── Web Application Attack Detector ────────────────────────────
	services.StartWebAttackScheduler()

	// ── Persistence Detector ────────────────────────────────────────
	services.StartPersistenceScheduler()

	// ── Insider Threat Score Engine ─────────────────────────────────
	services.StartInsiderThreatScheduler()

	// ── Cloud Security Detector (AWS CloudTrail / Azure / GCP) ──────────────
	services.StartCloudSecurityScheduler()

	// ── Email Security Detector (phishing, BEC, lookalike domains) ────────
	services.StartEmailSecurityScheduler()

	// ── Container / Kubernetes Security Detector ───────────────────
	services.StartContainerSecurityScheduler()

	// ── Active Directory Attack Detector (Kerberoasting, DCSync, PtH) ──────
	services.StartADAttackScheduler()

	// ── Supply Chain Attack Detector (curl|bash, dep confusion, typosquat) ──
	services.StartSupplyChainScheduler()

	// Process Injection + LSASS Credential Dump Detector
	services.StartProcessInjectionScheduler()

	// Defense Evasion Detector (log clear, AMSI bypass, UAC bypass, AV kill)
	services.StartDefenseEvasionScheduler()

	// OT / ICS Security Detector (Modbus, DNP3, SCADA, PLC)
	services.StartOTICSScheduler()

	// ── MDM compliance + command delivery ─────────────────────────
	services.StartMDMScheduler()

	// ── IOC auto-expiry (daily, disables never-fired / past-expiry IOCs) ──
	go services.StartIOCExpiryScheduler()

	// ── Deep Packet Inspection / Advanced Inspection ───────────────
	services.StartDGAScheduler()
	services.StartTLSAnomalyScheduler()
	services.StartHTTPInspectionScheduler()
	services.StartProtocolAnomalyScheduler()

	// ── Prometheus metrics refresh (every 30s) ────────────────
	// Deliberately NOT behind WithSingletonLock — Prometheus scrapes each
	// replica's /metrics independently (per-pod, not via the Service VIP),
	// so every replica must keep its own in-process gauges current.
	go func() {
		// Initial scrape so metrics are populated before first Prometheus poll
		services.RefreshMetrics()
		for {
			time.Sleep(30 * time.Second)
			services.RefreshMetrics()
		}
	}()

	loadAllowedOrigins()

	router := gin.Default()
	// Global multipart memory threshold: parts up to 8 MiB are buffered in RAM;
	// larger parts spill to temp files. Per-handler io.LimitReader caps still
	// enforce the real per-file size policy; this is a secondary backstop.
	router.MaxMultipartMemory = 8 << 20

	// CORS — explicit allowlist only; credentials are never sent to an
	// origin that isn't on the list (reflecting Origin + credentials:true
	// defeats CORS as a CSRF defense).
	router.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if allowedOrigins[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		c.Header("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	router.Use(middleware.SecurityHeaders())
	router.Use(middleware.RequestLogger())
	router.Use(middleware.RequestID())

	routes.SetupRoutes(router)

	// Real-time notification WebSocket — auth via ?ticket= (see IssueWSTicket).
	router.GET("/api/notifications/stream", api.NotificationsWS)

	// Prometheus metrics scrape endpoint — static bearer token (METRICS_TOKEN).
	router.GET("/metrics", middleware.RequireMetricsAuth(), api.MetricsHandler())

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		slog.Info("XCloak API running", "tls", true, "addr", ":8443")
		if err := router.RunTLS(":8443", certFile, keyFile); err != nil {
			log.Fatal("server exited: ", err)
		}
		return
	}

	slog.Info("XCloak API running", "addr", ":8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatal("server exited: ", err)
	}
}

// Copyright (c) 2025 Abhishek N. All rights reserved.
// Licensed under the Business Source License 1.1.
// See LICENSE in the project root for details.
