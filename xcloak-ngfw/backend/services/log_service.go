package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// SaveLogs normalizes each log line, stores the parsed fields, then runs
// detection. The normalization step runs synchronously on the ingest path
// so parsed_fields is populated immediately — no async pipeline needed.
func SaveLogs(logs []models.Log) error {

	// Normalize each log in-place before saving.
	for i := range logs {
		pf := NormalizeLog(logs[i].LogSource, logs[i].LogMessage)
		logs[i].ParsedFields = MarshalParsedFields(pf)
	}

	if err := repositories.SaveLogs(logs); err != nil {
		return err
	}

	// Run detection on every log line.
	for _, log := range logs {
		DetectThreats(log)
	}

	return nil
}
