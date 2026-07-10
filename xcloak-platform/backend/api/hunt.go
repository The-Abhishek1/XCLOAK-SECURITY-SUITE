package api

import (
	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/services"
)

// RunHunt — POST /api/hunt/run
// Body: { "query_type": "process", "query_text": "nmap", "save": true, "name": "Nmap scan" }
func RunHunt(c *gin.Context) {

	var body struct {
		QueryType string `json:"query_type"`
		QueryText string `json:"query_text"`
		Save      bool   `json:"save"`
		Name      string `json:"name"`
	}

	if err := c.ShouldBindJSON(&body); err != nil || body.QueryType == "" || body.QueryText == "" {
		c.JSON(400, gin.H{"error": "query_type and query_text are required"})
		return
	}

	queryID := 0
	tenantID := tenantIDFromContext(c)

	if body.Save {
		username, _ := c.Get("username")
		name := body.Name
		if name == "" {
			name = body.QueryType + ": " + body.QueryText
		}
		saved, err := services.SaveHuntQuery(models.HuntQuery{
			Name:      name,
			QueryType: body.QueryType,
			QueryText: body.QueryText,
			CreatedBy: username.(string),
		}, tenantID)
		if err == nil {
			queryID = saved.ID
		}
	}

	result, err := services.RunHuntQuery(queryID, body.QueryType, body.QueryText, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}

// GetHuntQueries — GET /api/hunt/queries
func GetHuntQueries(c *gin.Context) {
	queries, err := services.GetHuntQueries(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	if queries == nil {
		queries = []models.HuntQuery{}
	}
	c.JSON(200, queries)
}

// RerunHuntQuery — POST /api/hunt/queries/:id/run
func RerunHuntQuery(c *gin.Context) {
	id := c.Param("id")
	tenantID := tenantIDFromContext(c)

	q, err := services.GetHuntQueryByID(id, tenantID)
	if err != nil {
		c.JSON(404, gin.H{"error": "query not found"})
		return
	}

	result, err := services.RunHuntQuery(q.ID, q.QueryType, q.QueryText, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, result)
}

// DeleteHuntQuery — DELETE /api/hunt/queries/:id
func DeleteHuntQuery(c *gin.Context) {
	if err := services.DeleteHuntQuery(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"message": "deleted"})
}
