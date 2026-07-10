package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// SaveFileHashes persists the batch, then queues each hash for IOC matching.
// Matching runs async via StartIOCMatchConsumer when Kafka is enabled, so
// ingest latency doesn't scale with the IOC list size; falls back to
// matching inline when Kafka is disabled so detection still works locally.
func SaveFileHashes(hashes []models.FileHash) error {

	err := repositories.SaveFileHashes(hashes)
	if err != nil {
		return err
	}

	for _, hash := range hashes {
		if IsKafkaEnabled() {
			PublishFileHashMatchJob(hash)
		} else {
			CheckFileHashIOC(hash)
		}
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
