package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"time"

	"github.com/gin-gonic/gin"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
	"xcloak-platform/services"
)

// GenerateReport — POST /api/compliance/reports
func GenerateReport(c *gin.Context) {

	var body struct {
		ReportType string `json:"report_type"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.ReportType == "" {
		body.ReportType = "full"
	}

	username, _ := c.Get("username")
	generatedBy := fmt.Sprintf("%v", username)

	tenantID := tenantIDFromContext(c)

	report, err := services.GenerateComplianceReport(body.ReportType, generatedBy, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Compute framework scores for full reports.
	var frameworkScores interface{}
	if body.ReportType == "full" || body.ReportType == "" {
		scores, _ := services.ComputeAllFrameworkScores(report.ID, tenantID)
		frameworkScores = scores
	}

	c.JSON(200, gin.H{
		"report":           report,
		"framework_scores": frameworkScores,
	})
}

// GetReports — GET /api/compliance/reports
func GetReports(c *gin.Context) {

	reports, err := services.GetReports(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// FIX: use correct type instead of []interface{}
	if reports == nil {
		reports = []models.ComplianceReport{}
	}

	c.JSON(200, reports)
}

// GetReport — GET /api/compliance/reports/:id
func GetReport(c *gin.Context) {

	report, err := services.GetReportByID(c.Param("id"), tenantIDFromContext(c))
	if err != nil {
		c.JSON(404, gin.H{"error": "report not found"})
		return
	}

	c.JSON(200, report)
}

// DeleteReport — DELETE /api/compliance/reports/:id
func DeleteReport(c *gin.Context) {

	if err := services.DeleteReport(c.Param("id"), tenantIDFromContext(c)); err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	c.JSON(200, gin.H{"message": "Report deleted"})
}

// GetReportPDF — GET /api/compliance/reports/:id/pdf
func GetReportPDF(c *gin.Context) {
	tenantID := tenantIDFromContext(c)

	report, err := services.GetReportByID(c.Param("id"), tenantID)
	if err != nil {
		c.JSON(404, gin.H{"error": "report not found"})
		return
	}

	scores, err := services.GetFrameworkScores(report.ID, tenantID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	pdfBytes, err := services.GenerateCompliancePDF(report, scores)
	if err != nil {
		c.JSON(500, gin.H{"error": "failed to render PDF: " + err.Error()})
		return
	}

	filename := fmt.Sprintf("xcloak-compliance-report-%d.pdf", report.ID)
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Data(200, "application/pdf", pdfBytes)
}

// ExportAlertsCSV — GET /api/export/alerts
func ExportAlertsCSV(c *gin.Context) {

	alerts, err := repositories.GetAlerts(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	filename := fmt.Sprintf("xcloak-alerts-%s.csv", time.Now().Format("2006-01-02"))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Type", "text/csv")

	w := csv.NewWriter(c.Writer)
	w.Write([]string{"ID", "Agent ID", "Severity", "Rule Name", "MITRE Technique", "Log Message", "Created At"})

	for _, a := range alerts {
		w.Write([]string{
			fmt.Sprintf("%d", a.ID),
			fmt.Sprintf("%d", a.AgentID),
			a.Severity,
			a.RuleName,
			a.MitreTechnique,
			a.LogMessage,
			a.CreatedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
}

// ExportIncidentsCSV — GET /api/export/incidents
func ExportIncidentsCSV(c *gin.Context) {

	incidents, err := repositories.GetIncidents(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	filename := fmt.Sprintf("xcloak-incidents-%s.csv", time.Now().Format("2006-01-02"))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Type", "text/csv")

	w := csv.NewWriter(c.Writer)
	w.Write([]string{"ID", "Agent ID", "Title", "Severity", "Status", "Description", "Created At"})

	for _, i := range incidents {
		w.Write([]string{
			fmt.Sprintf("%d", i.ID),
			fmt.Sprintf("%d", i.AgentID),
			i.Title, i.Severity, i.Status,
			i.Description,
			i.CreatedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
}

// ExportVulnerabilitiesCSV — GET /api/export/vulnerabilities
func ExportVulnerabilitiesCSV(c *gin.Context) {

	vulns, err := repositories.GetVulnerabilities(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	filename := fmt.Sprintf("xcloak-vulnerabilities-%s.csv", time.Now().Format("2006-01-02"))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Type", "text/csv")

	w := csv.NewWriter(c.Writer)
	w.Write([]string{"ID", "Agent ID", "CVE ID", "Package", "Version", "Severity", "CVSS Score", "Name", "Remediation", "Detected At"})

	for _, v := range vulns {
		w.Write([]string{
			fmt.Sprintf("%d", v.ID),
			fmt.Sprintf("%d", v.AgentID),
			v.CVEID, v.PackageName, v.PackageVersion,
			v.Severity,
			fmt.Sprintf("%.1f", v.CVSSScore),
			v.Name, v.Remediation,
			v.DetectedAt.Format(time.RFC3339),
		})
	}
	w.Flush()
}

// ExportAuditJSON — GET /api/export/audit
func ExportAuditJSON(c *gin.Context) {

	logs, err := repositories.GetAuditLogs(tenantIDFromContext(c))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	filename := fmt.Sprintf("xcloak-audit-%s.json", time.Now().Format("2006-01-02"))
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	c.Header("Content-Type", "application/json")

	c.JSON(200, gin.H{
		"exported_at": time.Now().Format(time.RFC3339),
		"count":       len(logs),
		"logs":        logs,
	})
}

// GetCVEDetails — GET /api/cve/:id
func GetCVEDetails(c *gin.Context) {

	cveID := c.Param("id")
	if cveID == "" {
		c.JSON(400, gin.H{"error": "cve id required"})
		return
	}

	details, err := services.GetCVEDetails(cveID)
	if err != nil {
		c.JSON(502, gin.H{"error": "NVD lookup failed: " + err.Error()})
		return
	}

	c.JSON(200, details)
}

// suppress unused import warning
var _ = json.Marshal
