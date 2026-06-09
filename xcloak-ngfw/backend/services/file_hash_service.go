package services

import (
	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// SaveFileHashes persists the batch and immediately runs IOC matching
// against every hash. Matching is synchronous so alerts appear before
// the API response returns — acceptable at current scale, move to a
// goroutine + channel when batch sizes exceed ~10k files.
func SaveFileHashes(hashes []models.FileHash) error {

	err := repositories.SaveFileHashes(hashes)
	if err != nil {
		return err
	}

	for _, hash := range hashes {
		CheckFileHashIOC(hash)
	}

	return nil
}

// GetFileHashesByAgent returns stored hashes for a given agent.
func GetFileHashesByAgent(agentID string) ([]models.FileHash, error) {
	return repositories.GetFileHashesByAgent(agentID)
}

// GetFileHashCount returns how many files have been indexed for an agent.
func GetFileHashCount(agentID string) (int, error) {
	return repositories.GetFileHashCount(agentID)
}
