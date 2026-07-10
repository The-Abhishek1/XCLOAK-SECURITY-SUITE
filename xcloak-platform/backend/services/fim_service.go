package services

import (
	"fmt"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
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
			// File modified — deliberately do NOT update the baseline here.
			// Auto-overwriting on every modified event meant a single
			// tampered file silently became the new "good" baseline, so
			// repeat tampering (or persistence re-writing the same file)
			// never re-alerted. The baseline now only changes via an
			// explicit AcceptFIMBaseline call (see api/fim.go), so this
			// keeps re-detecting the drift on every scan until an analyst
			// reviews and accepts it.
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

// AcceptFIMBaseline re-baselines a single file to the hash from its most
// recent detected change — the explicit action that replaces the old
// automatic re-baselining. Looks the hash up server-side from the alert
// trail rather than trusting a client-submitted hash, so accepting a
// change can't be used to plant an arbitrary baseline value.
func AcceptFIMBaseline(agentID int, filePath string) error {
	latest, err := repositories.GetLatestFIMAlert(agentID, filePath)
	if err != nil {
		return err
	}
	if latest == nil {
		return fmt.Errorf("no FIM alert found for %s on agent %d", filePath, agentID)
	}
	if latest.ChangeType == "deleted" {
		return repositories.DeleteFIMEntry(agentID, filePath)
	}
	return repositories.UpsertFIMEntry(models.FIMBaseline{
		AgentID:  agentID,
		FilePath: filePath,
		SHA256:   latest.NewHash,
	})
}

func createFIMChange(agentID int, path, changeType, oldHash, newHash string) {

	repositories.CreateFIMAlert(models.FIMAlert{
		AgentID:    agentID,
		FilePath:   path,
		ChangeType: changeType,
		OldHash:    oldHash,
		NewHash:    newHash,
	})

	go PublishFIMAlert(agentID, path, changeType, newHash)

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
