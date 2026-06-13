package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// GetAgentProcesses returns recent processes collected for an agent.
// Route: GET /api/agents/:id/processes
func GetAgentProcesses(c *gin.Context) {

	id := c.Param("id")

	rows, err := repositories.GetProcessesByAgent(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rows == nil {
		rows = []models.Process{}
	}

	c.JSON(http.StatusOK, rows)
}

// GetAgentConnections returns recent connections for an agent.
// Route: GET /api/agents/:id/connections
func GetAgentConnections(c *gin.Context) {

	id := c.Param("id")

	rows, err := repositories.GetConnectionsByAgent(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rows == nil {
		rows = []models.Connection{}
	}

	c.JSON(http.StatusOK, rows)
}

// GetAgentServicesList returns all services for an agent.
// Route: GET /api/agents/:id/services
func GetAgentServicesList(c *gin.Context) {

	id := c.Param("id")

	rows, err := repositories.GetServicesByAgent(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rows == nil {
		rows = []models.Service{}
	}

	c.JSON(http.StatusOK, rows)
}

// GetAgentUsersList returns all OS users for an agent.
// Route: GET /api/agents/:id/users
func GetAgentUsersList(c *gin.Context) {

	id := c.Param("id")

	rows, err := repositories.GetUsersByAgent(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rows == nil {
		rows = []models.Users{}
	}

	c.JSON(http.StatusOK, rows)
}

// GetAgentPackagesList returns all packages for an agent.
// Route: GET /api/agents/:id/packages
func GetAgentPackagesList(c *gin.Context) {

	id := c.Param("id")

	rows, err := repositories.GetAgentPackagesList(id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if rows == nil {
		rows = []models.Package{}
	}

	c.JSON(http.StatusOK, rows)
}
