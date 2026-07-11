package services

import (
	"fmt"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// ProcessFIMScan compares the incoming scan results against the stored
// baseline and raises an alert for any change — hash modification, file
// permission change (chmod), or ownership change (chown). On the first
// scan (no baseline yet) it establishes the baseline silently.
func ProcessFIMScan(payload models.FIMScanPayload) error {

	baseline, err := repositories.GetFIMBaseline(payload.AgentID)
	if err != nil {
		return err
	}

	baselineMap := make(map[string]models.FIMBaseline, len(baseline))
	for _, b := range baseline {
		baselineMap[b.FilePath] = b
	}

	scannedPaths := make(map[string]bool)

	for _, f := range payload.Files {
		scannedPaths[f.FilePath] = true
		existing, known := baselineMap[f.FilePath]

		if !known {
			repositories.UpsertFIMEntry(fileEntryToBaseline(payload.AgentID, f))
			if len(baseline) > 0 {
				createFIMChange(payload.AgentID, f.FilePath, "created", models.FIMAlert{
					NewHash: f.SHA256,
					NewMode: f.Mode,
					NewUID:  f.UID,
				})
			}
			continue
		}

		hashChanged := existing.SHA256 != f.SHA256
		// Permission or ownership changed when the agent reports non-empty mode
		// and it differs from the stored baseline — catching chmod/chown attacks
		// that don't alter file content (e.g., adding the setuid bit).
		permChanged := f.Mode != "" && (existing.FileMode != f.Mode || existing.FileUID != f.UID)

		switch {
		case hashChanged && permChanged:
			// Both content and permissions changed — record all deltas.
			createFIMChange(payload.AgentID, f.FilePath, "modified", models.FIMAlert{
				OldHash: existing.SHA256, NewHash: f.SHA256,
				OldMode: existing.FileMode, NewMode: f.Mode,
				OldUID: existing.FileUID, NewUID: f.UID,
			})
		case hashChanged:
			createFIMChange(payload.AgentID, f.FilePath, "modified", models.FIMAlert{
				OldHash: existing.SHA256, NewHash: f.SHA256,
				OldMode: existing.FileMode, NewMode: f.Mode,
			})
		case permChanged:
			// Hash unchanged but permissions/ownership drifted — this is the
			// classic setuid-backdoor pattern: attacker adds the s bit to a
			// binary without touching its contents.
			createFIMChange(payload.AgentID, f.FilePath, "permission_change", models.FIMAlert{
				OldHash: existing.SHA256, NewHash: existing.SHA256,
				OldMode: existing.FileMode, NewMode: f.Mode,
				OldUID: existing.FileUID, NewUID: f.UID,
			})
		}
	}

	if len(baseline) > 0 {
		for path := range baselineMap {
			if !scannedPaths[path] {
				createFIMChange(payload.AgentID, path, "deleted", models.FIMAlert{
					OldHash: baselineMap[path].SHA256,
					OldMode: baselineMap[path].FileMode,
				})
			}
		}
	}

	return nil
}

// AcceptFIMBaseline re-baselines a single file to the state from its most
// recent alert — the analyst's explicit sign-off replaces the old automatic
// re-baselining that silently accepted tampered files.
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
		FileMode: latest.NewMode,
		FileUID:  latest.NewUID,
	})
}

func fileEntryToBaseline(agentID int, f models.FIMFileEntry) models.FIMBaseline {
	return models.FIMBaseline{
		AgentID:  agentID,
		FilePath: f.FilePath,
		SHA256:   f.SHA256,
		FileSize: f.FileSize,
		FileMode: f.Mode,
		FileUID:  f.UID,
		FileGID:  f.GID,
		ModTime:  f.ModTime,
	}
}

func createFIMChange(agentID int, path, changeType string, delta models.FIMAlert) {
	delta.AgentID = agentID
	delta.FilePath = path
	delta.ChangeType = changeType
	repositories.CreateFIMAlert(delta)

	go PublishFIMAlert(agentID, path, changeType, delta.NewHash)

	severity := "high"
	if changeType == "created" {
		severity = "medium"
	}

	logMsg := fmt.Sprintf("%s: %s", changeType, path)
	if delta.OldHash != "" {
		logMsg += fmt.Sprintf(" (hash was: %s)", truncate(delta.OldHash, 12))
	}
	if delta.OldMode != "" && delta.NewMode != "" && delta.OldMode != delta.NewMode {
		logMsg += fmt.Sprintf(" [mode: %s → %s]", delta.OldMode, delta.NewMode)
	}

	CreateAlert(models.Alert{
		AgentID:        agentID,
		Severity:       severity,
		RuleName:       "File Integrity Violation",
		LogMessage:     logMsg,
		MitreTactic:    "Defense Evasion",
		MitreTechnique: "T1565",
		MitreName:      "Data Manipulation",
		Fingerprint:    fmt.Sprintf("fim-%d-%s-%s", agentID, changeType, path),
	})
}
