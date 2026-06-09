package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

func ImportIOCs(
	req models.IOCImportRequest,
) models.IOCImportResult {

	result := models.IOCImportResult{}

	for _, indicator := range req.Indicators {

		if repositories.IOCExists(
			indicator,
			req.Type,
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
		)

		result.Imported++
	}

	return result
}
