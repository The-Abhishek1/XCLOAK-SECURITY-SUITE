package main

import (
	"log"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/joho/godotenv"

	"xcloak-ngfw/api"
	"xcloak-ngfw/database"
	"xcloak-ngfw/middleware"
	"xcloak-ngfw/models"
	"xcloak-ngfw/routes"
	"xcloak-ngfw/secrets"
	"xcloak-ngfw/services"
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
		log.Println("[Vault] could not ensure TOTP transit key, 2FA endpoints will fail until resolved:", err)
	}

	err := database.Connect()
	if err != nil {
		panic(err)
	}

	if err := database.Migrate(); err != nil {
		panic(err)
	}

	services.InitRedis()

	// ── Immutable audit log export (MinIO + Object Lock) ──────
	// Non-fatal: audit export is a compliance nice-to-have, not a hard
	// dependency for the API to serve traffic.
	if err := services.InitMinIO(); err != nil {
		log.Println("[AuditExport] MinIO unavailable, audit export disabled:", err)
	} else {
		go services.StartAuditExportScheduler()
	}

	// ── Kafka event bus ──────────────────────────────────────
	services.InitKafka()
	defer services.CloseKafka()
	go services.StartIOCMatchConsumer()

	// Wire WebSocket alert broadcaster (avoids import cycle: services ↔ api).
	services.RegisterBroadcastFn(func(alert models.Alert) {
		api.BroadcastAlert(alert)
	})

	// Start background scheduler for recurring agent tasks.
	go services.StartScheduler()
	go services.StartHealthScheduler()
	go services.StartKEVRefreshScheduler()

	go func() {
		for {
			services.WithSingletonLock("mark_offline_agents", services.MarkOfflineAgents)
			time.Sleep(30 * time.Second)
		}
	}()

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

	router.Use(middleware.RequestLogger())
	router.Use(middleware.RequestID())

	routes.SetupRoutes(router)

	// Real-time notification WebSocket (separate from log stream).
	router.GET("/api/notifications/stream",
		middleware.RequireAuth(),
		api.NotificationsWS,
	)

	// Prometheus metrics scrape endpoint — static bearer token (METRICS_TOKEN).
	router.GET("/metrics", middleware.RequireMetricsAuth(), api.MetricsHandler())

	certFile := os.Getenv("TLS_CERT_FILE")
	keyFile := os.Getenv("TLS_KEY_FILE")
	if certFile != "" && keyFile != "" {
		log.Println("XCloak API Running (TLS)")
		if err := router.RunTLS(":8443", certFile, keyFile); err != nil {
			log.Fatal("server exited: ", err)
		}
		return
	}

	log.Println("XCloak API Running")
	if err := router.Run(":8080"); err != nil {
		// Was previously discarded — a port already in use (e.g. a stale
		// process from a prior run) made the process exit silently right
		// after printing every other startup log, looking deceptively healthy.
		log.Fatal("server exited: ", err)
	}
}
