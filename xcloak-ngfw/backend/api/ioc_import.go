package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/services"
)

func ImportIOCs(
	c *gin.Context,
) {

	var req models.IOCImportRequest

	if err := c.ShouldBindJSON(
		&req,
	); err != nil {

		c.JSON(
			400,
			gin.H{
				"error": err.Error(),
			},
		)

		return
	}

	result := services.ImportIOCs(
		req,
	)

	c.JSON(
		200,
		gin.H{
			"message":   "IOCs Imported",
			"imported":  result.Imported,
			"skipped":   result.Skipped,
			"submitted": len(req.Indicators),
		},
	)
}
