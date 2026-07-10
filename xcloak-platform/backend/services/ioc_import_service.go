package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func ImportIOCs(
	req models.IOCImportRequest,
	tenantID int,
) models.IOCImportResult {

	result := models.IOCImportResult{}

	for _, indicator := range req.Indicators {

		if repositories.IOCExists(
			indicator,
			req.Type,
			tenantID,
		) {

			result.Skipped++
			continue
		}

		CreateIOC(
			models.IOC{
				Indicator:   indicator,
				Type:        req.Type,
				Severity:    req.Severity,
				Description: req.Description,
				Enabled:     true,
			},
			tenantID,
		)

		result.Imported++
	}

	return result
}
