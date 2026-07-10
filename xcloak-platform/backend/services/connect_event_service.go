package services

import (
	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// SaveConnectEvents persists eBPF-sourced connection events and runs them
// through the same IOC-matching path as the periodic ss-based snapshot
// (CheckConnectionIOC/PublishConnectionMatchJob) — real-time connects get
// IOC matching for free, faster than the old 5-minute-polled path, since
// these events arrive within moments of the actual connect() syscall.
func SaveConnectEvents(events []models.ConnectEvent) error {
	if err := repositories.SaveConnectEvents(events); err != nil {
		return err
	}

	for _, ev := range events {
		conn := models.Connection{
			AgentID:       ev.AgentID,
			RemoteAddress: ev.RemoteAddress,
		}
		if IsKafkaEnabled() {
			PublishConnectionMatchJob(conn)
		} else {
			CheckConnectionIOC(conn)
		}
	}

	return nil
}

func GetConnectEvents(agentID int) ([]models.ConnectEvent, error) {
	return repositories.GetConnectEventsByAgent(agentID, 200)
}
