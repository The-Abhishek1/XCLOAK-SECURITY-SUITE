package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/services"
)

func GetAttackPathGraph(c *gin.Context) {

	graph, err := services.BuildAttackPathGraph(tenantIDFromContext(c))

	if err != nil {

		c.JSON(500, gin.H{
			"error": err.Error(),
		})

		return
	}

	c.JSON(200, graph)
}
