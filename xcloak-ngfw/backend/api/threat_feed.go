package api

import (
	"encoding/json"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func CreateThreatFeed(
	c *gin.Context,
) {

	var feed models.ThreatFeed

	if err := c.ShouldBindJSON(
		&feed,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	err := services.CreateThreatFeed(
		feed,
		tenantIDFromContext(c),
	)

	if err != nil {

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	c.JSON(
		200,
		gin.H{
			"message": "Feed Created",
		},
	)
}

func GetThreatFeeds(
	c *gin.Context,
) {

	feeds, err := services.GetThreatFeeds(tenantIDFromContext(c))

	if err != nil {

		c.JSON(
			500,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	// Redact credentials — this endpoint is RequireAuth() only, not
	// admin-gated, so an analyst-role user can hit it too.
	for i := range feeds {
		var cfg models.ThreatFeedConfig
		if json.Unmarshal(feeds[i].Config, &cfg) == nil {
			if cfg.APIKey != "" {
				cfg.APIKey = "••••••••"
			}
			if cfg.Password != "" {
				cfg.Password = "••••••••"
			}
			redacted, _ := json.Marshal(cfg)
			feeds[i].Config = redacted
		}
	}

	c.JSON(
		200,
		feeds,
	)
}
