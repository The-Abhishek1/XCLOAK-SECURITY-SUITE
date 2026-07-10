package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/database"
	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// startTime is set when the package is first loaded so DeepHealth can report
// process uptime.
var startTime = time.Now()

func CreateRule(c *gin.Context) {

	var rule models.FirewallRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	err := services.CreateFirewallRule(rule, tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule Created",
	})
}

func GetRules(c *gin.Context) {

	rules, err := repositories.GetRulesForTenant(tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	c.JSON(http.StatusOK, rules)
}

func GetRuleByID(c *gin.Context) {

	id := c.Param("id")

	rule, err := repositories.GetRuleByID(id, tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, rule)
}

func UpdateRule(c *gin.Context) {

	id := c.Param("id")

	var rule models.FirewallRule

	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": err.Error(),
		})
		return
	}

	rowsAffected, err := repositories.UpdateRule(
		id,
		rule,
		tenantIDFromContext(c),
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule Updated",
	})
}

func DeleteRule(c *gin.Context) {

	id := c.Param("id")

	rowsAffected, err := repositories.DeleteRule(id, tenantIDFromContext(c))

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": err.Error(),
		})
		return
	}

	if rowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{
			"error": "Rule not found",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Rule Deleted",
	})
}

// Health — GET /api/health
// Shallow check: returns 200 as long as the process is alive and the circuit
// is closed. Load balancers use this endpoint; it intentionally avoids slow
// DB queries so a degraded-but-live backend doesn't flap the LB.
func Health(c *gin.Context) {
	circuit := database.GetCircuitHealth()
	status := http.StatusOK
	health := "healthy"
	if database.IsPrimaryDown() {
		status = http.StatusServiceUnavailable
		health = "degraded"
	}
	c.JSON(status, gin.H{
		"status":  health,
		"service": "xcloak-platform",
		"circuit": circuit,
	})
}

// DeepHealth — GET /api/health/deep
// Executes a real SELECT 1 on both primary and replica, measures latency, and
// returns pool stats + replication lag. Used by monitoring dashboards, not LBs.
func DeepHealth(c *gin.Context) {
	type dbResult struct {
		Reachable   bool              `json:"reachable"`
		LatencyMs   float64           `json:"latency_ms"`
		Pool        database.DBStats  `json:"pool"`
		ReplicaLag  float64           `json:"replica_lag_seconds,omitempty"`
	}

	pingLatency := func(db *sql.DB) (bool, float64) {
		if db == nil {
			return false, 0
		}
		start := time.Now()
		err := db.Ping()
		ms := float64(time.Since(start).Microseconds()) / 1000.0
		return err == nil, ms
	}

	primaryOK, primaryLatency := pingLatency(database.DB)
	replicaOK, replicaLatency := pingLatency(database.ReadDB)

	status := http.StatusOK
	overallHealth := "healthy"
	if !primaryOK {
		status = http.StatusServiceUnavailable
		overallHealth = "degraded"
	}

	primary := dbResult{
		Reachable: primaryOK,
		LatencyMs: primaryLatency,
		Pool:      database.PrimaryStats(),
	}

	var replica *dbResult
	if database.ReadDB != nil {
		lag := database.ReplicaLagSeconds()
		replica = &dbResult{
			Reachable:  replicaOK,
			LatencyMs:  replicaLatency,
			Pool:       database.ReplicaStats(),
			ReplicaLag: lag,
		}
		if lag > 30 {
			overallHealth = "degraded" // replica significantly behind
		}
	}

	c.JSON(status, gin.H{
		"status":  overallHealth,
		"service": "xcloak-platform",
		"uptime":  time.Since(startTime).String(),
		"circuit": database.GetCircuitHealth(),
		"primary": primary,
		"replica": replica,
	})
}
