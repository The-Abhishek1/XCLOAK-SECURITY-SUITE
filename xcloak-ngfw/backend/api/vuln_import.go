package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"xcloak-ngfw/services"
)

// ImportVulnScan accepts a multipart/form-data upload of a scanner XML file.
// POST /api/vulns/import
//
// Form fields:
//   file — the scanner XML file (.nessus, Qualys XML, Tenable.sc XML)
func ImportVulnScan(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	userID := userIDFromContext(c)

	fileHeader, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing file field"})
		return
	}

	if fileHeader.Size > 200*1024*1024 {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "file exceeds 200 MB limit"})
		return
	}

	f, err := fileHeader.Open()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "cannot open upload"})
		return
	}
	defer f.Close()

	result, err := services.ImportScannerXML(tenantID, userID, fileHeader.Filename, f)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"scanner":    result.Scanner,
		"host_count": result.HostCount,
		"vuln_count": result.VulnCount,
		"new_count":  result.NewCount,
		"message":    "import complete",
	})
}

// ListVulnImports returns the import history for the authenticated tenant.
// GET /api/vulns/imports
func ListVulnImports(c *gin.Context) {
	tenantID := tenantIDFromContext(c)
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	records, err := services.ListScanImports(tenantID, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"imports": records})
}
