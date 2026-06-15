package api

import (
	"github.com/gin-gonic/gin"
	"xcloak-ngfw/services"
)

// GetKafkaStatus — GET /api/kafka/status
// Returns whether Kafka is connected and the configured broker.
func GetKafkaStatus(c *gin.Context) {
	c.JSON(200, gin.H{
		"enabled": services.IsKafkaEnabled(),
		"topics": []string{
			"xcloak.alerts",
			"xcloak.incidents",
			"xcloak.agent_tasks",
			"xcloak.audit",
			"xcloak.fim_alerts",
			"xcloak.yara_matches",
		},
	})
}
