package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
	"xcloak-ngfw/services"
)

func CreateCase(c *gin.Context) {
	var req models.Case
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.TenantID = tenantIDFromContext(c)
	uid := userIDFromContext(c)
	uname := usernameFromContext(c)
	req.AssignedTo = nil
	if uid > 0 {
		req.AssignedTo = &uid
		req.AssignedToName = uname
	}
	cas, err := services.CreateCase(req, uid, uname)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, cas)
}

func GetCases(c *gin.Context) {
	tid := tenantIDFromContext(c)
	page, _ := strconv.Atoi(c.DefaultQuery("page", "0"))
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	if limit > 200 {
		limit = 200
	}
	status := c.Query("status")
	severity := c.Query("severity")
	cases, total, err := repositories.GetCases(tid, page, limit, status, severity)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if cases == nil {
		cases = []models.Case{}
	}
	c.JSON(http.StatusOK, gin.H{"cases": cases, "total": total, "page": page})
}

func GetCaseByID(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	cas, err := repositories.GetCaseByID(id, tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "case not found"})
		return
	}
	comments, _ := repositories.GetCaseComments(id, tenantIDFromContext(c))
	evidence, _ := repositories.GetCaseEvidence(id, tenantIDFromContext(c))
	alerts, _ := repositories.GetCaseAlerts(id, tenantIDFromContext(c))
	if comments == nil {
		comments = []models.CaseComment{}
	}
	if evidence == nil {
		evidence = []models.CaseEvidence{}
	}
	if alerts == nil {
		alerts = []models.Alert{}
	}
	c.JSON(http.StatusOK, gin.H{
		"case":     cas,
		"comments": comments,
		"evidence": evidence,
		"alerts":   alerts,
	})
}

func UpdateCase(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req models.Case
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	req.ID = id
	req.TenantID = tenantIDFromContext(c)
	if err := services.UpdateCase(req, usernameFromContext(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func DeleteCase(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	if err := repositories.DeleteCase(id, tenantIDFromContext(c)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func AddCaseComment(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct{ Body string `json:"body"` }
	c.ShouldBindJSON(&req)
	uid := userIDFromContext(c)
	comment, err := repositories.AddCaseComment(models.CaseComment{
		CaseID:   id,
		UserID:   &uid,
		Username: usernameFromContext(c),
		Body:     req.Body,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, comment)
}

func AddCaseEvidence(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req models.CaseEvidence
	c.ShouldBindJSON(&req)
	req.CaseID = id
	uid := userIDFromContext(c)
	req.AddedBy = &uid
	req.AddedByName = usernameFromContext(c)
	ev, err := repositories.AddCaseEvidence(req)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusCreated, ev)
}

func LinkAlertToCase(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	var req struct{ AlertID int `json:"alert_id"` }
	c.ShouldBindJSON(&req)
	if err := repositories.LinkAlertToCase(id, req.AlertID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func UnlinkAlertFromCase(c *gin.Context) {
	id, _ := strconv.Atoi(c.Param("id"))
	alertID, _ := strconv.Atoi(c.Param("alert_id"))
	repositories.UnlinkAlertFromCase(id, alertID)
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func GetExecutiveMetrics(c *gin.Context) {
	metrics, err := services.BuildExecutiveMetrics(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, metrics)
}

func DownloadExecutiveReport(c *gin.Context) {
	metrics, err := services.BuildExecutiveMetrics(tenantIDFromContext(c))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", "attachment; filename=\"executive-report.pdf\"")
	if err := services.GenerateExecutivePDF(c.Writer, metrics, "Executive Security Report"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
	}
}
