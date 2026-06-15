package main

import (
	"log"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/api"
	"xcloak-ngfw/database"
	"xcloak-ngfw/middleware"
	"xcloak-ngfw/models"
	"xcloak-ngfw/routes"
	"xcloak-ngfw/services"
)

func main() {

	err := database.Connect()
	if err != nil {
		panic(err)
	}

	// ── Kafka event bus ──────────────────────────────────────
	services.InitKafka()
	defer services.CloseKafka()

	// Wire WebSocket alert broadcaster (avoids import cycle: services ↔ api).
	services.RegisterBroadcastFn(func(alert models.Alert) {
		api.BroadcastAlert(alert)
	})

	// Start background scheduler for recurring agent tasks.
	go services.StartScheduler()
	go services.StartHealthScheduler()

	go func() {
		for {
			services.MarkOfflineAgents()
			time.Sleep(30 * time.Second)
		}
	}()

	// ── Prometheus metrics refresh (every 30s) ────────────────
	go func() {
		// Initial scrape so metrics are populated before first Prometheus poll
		services.RefreshMetrics()
		for {
			time.Sleep(30 * time.Second)
			services.RefreshMetrics()
		}
	}()

	router := gin.Default()

	// CORS — allow WS from Next.js dev server.
	router.Use(func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			origin = "*"
		}
		c.Header("Access-Control-Allow-Origin", origin)
		c.Header("Access-Control-Allow-Credentials", "true")
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

	// Prometheus metrics scrape endpoint — no auth, restrict via network.
	router.GET("/metrics", api.MetricsHandler())

	log.Println("XCloak API Running")
	router.Run(":8080")
}
