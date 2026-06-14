package services

import (
	"fmt"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// ProcessFIMScan compares the incoming scan results against the stored
// baseline and raises an alert + FIM alert record for any change.
// On first scan (no baseline yet), it establishes the baseline silently.
func ProcessFIMScan(payload models.FIMScanPayload) error {

	baseline, err := repositories.GetFIMBaseline(payload.AgentID)
	if err != nil {
		return err
	}

	// Index baseline by path for O(1) lookup.
	baselineMap := make(map[string]models.FIMBaseline, len(baseline))
	for _, b := range baseline {
		baselineMap[b.FilePath] = b
	}

	// Track which paths are in the current scan.
	scannedPaths := make(map[string]bool)

	for _, f := range payload.Files {

		scannedPaths[f.FilePath] = true
		existing, known := baselineMap[f.FilePath]

		if !known {
			// New file — add to baseline (first scan or genuinely new file).
			repositories.UpsertFIMEntry(models.FIMBaseline{
				AgentID:  payload.AgentID,
				FilePath: f.FilePath,
				SHA256:   f.SHA256,
				FileSize: f.FileSize,
			})
			if len(baseline) > 0 {
				// Only alert if a baseline already exists (new file added post-baseline).
				createFIMChange(payload.AgentID, f.FilePath, "created", "", f.SHA256)
			}
			continue
		}

		if existing.SHA256 != f.SHA256 {
			// File modified.
			repositories.UpsertFIMEntry(models.FIMBaseline{
				AgentID:  payload.AgentID,
				FilePath: f.FilePath,
				SHA256:   f.SHA256,
				FileSize: f.FileSize,
			})
			createFIMChange(payload.AgentID, f.FilePath, "modified", existing.SHA256, f.SHA256)
		}
	}

	// Detect deleted files.
	if len(baseline) > 0 {
		for path := range baselineMap {
			if !scannedPaths[path] {
				createFIMChange(payload.AgentID, path, "deleted", baselineMap[path].SHA256, "")
			}
		}
	}

	return nil
}

func createFIMChange(agentID int, path, changeType, oldHash, newHash string) {

	repositories.CreateFIMAlert(models.FIMAlert{
		AgentID:    agentID,
		FilePath:   path,
		ChangeType: changeType,
		OldHash:    oldHash,
		NewHash:    newHash,
	})

	severity := "high"
	if changeType == "created" {
		severity = "medium"
	}

	CreateAlert(models.Alert{
		AgentID:        agentID,
		Severity:       severity,
		RuleName:       "File Integrity Violation",
		LogMessage:     fmt.Sprintf("%s: %s (was: %s)", changeType, path, truncate(oldHash, 12)),
		MitreTactic:    "Defense Evasion",
		MitreTechnique: "T1565",
		MitreName:      "Data Manipulation",
		Fingerprint:    fmt.Sprintf("fim-%d-%s-%s", agentID, changeType, path),
	})
}
