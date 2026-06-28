package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func GetScheduledReports(c *gin.Context) {
	reports, err := repositories.GetScheduledReports(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if reports == nil {
		reports = []models.ScheduledReport{}
	}
	c.JSON(http.StatusOK, reports)
}

func CreateScheduledReport(c *gin.Context) {
	var req models.ScheduledReport
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.TenantID = tenantIDFromContext(c)
	uid := userIDFromContext(c)
	req.CreatedBy = &uid
	if req.Recipients == nil {
		req.Recipients = []string{}
	}
	r, err := repositories.CreateScheduledReport(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, r)
}

func UpdateScheduledReport(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req models.ScheduledReport
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.ID = id
	req.TenantID = tenantIDFromContext(c)
	if req.Recipients == nil {
		req.Recipients = []string{}
	}
	if err := repositories.UpdateScheduledReport(req); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteScheduledReport(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := repositories.DeleteScheduledReport(id, tenantIDFromContext(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}
