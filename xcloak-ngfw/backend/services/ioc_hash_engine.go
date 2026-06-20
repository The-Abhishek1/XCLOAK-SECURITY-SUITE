package services

import (
	"fmt"
	"strings"

	"xcloak-ngfw/models"
)

// CheckFileHashIOC checks a single file hash against all enabled hash-type IOCs.
//
// BUG FIX: The original fingerprint was just the hash value. This caused alert
// deduplication to suppress the same malware on a second agent — the fingerprint
// already existed in alerts from the first hit. Fingerprint now includes agent_id
// so each agent gets its own alert.
func CheckFileHashIOC(hash models.FileHash) {

	iocs, err := GetEnabledIOCsForAgent(hash.AgentID)
	if err != nil {
		return
	}

	for _, ioc := range iocs {

		switch ioc.Type {

		case "sha256":

			if strings.EqualFold(hash.SHA256Hash, ioc.Indicator) {

				fingerprint := fmt.Sprintf(
					"ioc-sha256-%s-agent-%d",
					hash.SHA256Hash,
					hash.AgentID,
				)

				CreateAlert(models.Alert{
					AgentID:        hash.AgentID,
					Severity:       ioc.Severity,
					RuleName:       "IOC: Malicious File Hash (SHA256)",
					LogMessage:     buildHashAlertMessage(hash, ioc, "SHA256"),
					MitreTactic:    "Execution",
					MitreTechnique: "T1204",
					MitreName:      "User Execution",
					Fingerprint:    fingerprint,
				})
			}

		case "md5":

			if strings.EqualFold(hash.MD5Hash, ioc.Indicator) {

				fingerprint := fmt.Sprintf(
					"ioc-md5-%s-agent-%d",
					hash.MD5Hash,
					hash.AgentID,
				)

				CreateAlert(models.Alert{
					AgentID:        hash.AgentID,
					Severity:       ioc.Severity,
					RuleName:       "IOC: Malicious File Hash (MD5)",
					LogMessage:     buildHashAlertMessage(hash, ioc, "MD5"),
					MitreTactic:    "Execution",
					MitreTechnique: "T1204",
					MitreName:      "User Execution",
					Fingerprint:    fingerprint,
				})
			}
		}
	}
}

// buildHashAlertMessage produces a human-readable log message for the alert,
// giving the analyst enough context without opening a separate query.
func buildHashAlertMessage(
	hash models.FileHash,
	ioc models.IOC,
	hashType string,
) string {

	return fmt.Sprintf(
		"Malicious file detected on agent %d | File: %s | %s: %s | IOC: %s | Reason: %s",
		hash.AgentID,
		hash.FilePath,
		hashType,
		ioc.Indicator,
		ioc.Description,
		ioc.Description,
	)
}
