package services

import (
	"log/slog"
	"time"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

func CreateIOC(
	ioc models.IOC,
	tenantID int,
) error {

	return repositories.CreateIOC(ioc, tenantID)
}

func GetIOCs(tenantID int) ([]models.IOC, error) {

	return repositories.GetIOCs(tenantID)
}

// GetAllIOCs returns every IOC across every tenant — for internal
// background jobs only, see repositories.GetAllIOCs.
func GetAllIOCs() ([]models.IOC, error) {

	return repositories.GetAllIOCs()
}

// GetEnabledIOCsForAgent returns enabled IOCs for the tenant that owns
// agentID — used by the connection/file-hash matching engines.
func GetEnabledIOCsForAgent(agentID int) ([]models.IOC, error) {

	return repositories.GetEnabledIOCsForAgent(agentID)
}

func GetIOCByID(
	id string,
	tenantID int,
) (*models.IOC, error) {

	return repositories.GetIOCByID(id, tenantID)
}

func UpdateIOC(
	id string,
	ioc models.IOC,
	tenantID int,
) error {

	return repositories.UpdateIOC(
		id,
		ioc,
		tenantID,
	)
}

func DeleteIOC(
	id string,
	tenantID int,
) error {

	return repositories.DeleteIOC(id, tenantID)
}

func EnableIOC(
	id string,
	tenantID int,
) error {

	return repositories.EnableIOC(id, tenantID)
}

func DisableIOC(
	id string,
	tenantID int,
) error {

	return repositories.DisableIOC(id, tenantID)
}

// StartIOCExpiryScheduler runs a daily job that auto-disables IOCs which have
// exceeded their expires_at date or have never fired and are older than 90 days.
func StartIOCExpiryScheduler() {
	for {
		n, err := repositories.ExpireStaleIOCs(90)
		if err != nil {
			slog.Error("IOCExpiry: failed to expire stale IOCs", "err", err)
		} else if n > 0 {
			slog.Info("IOCExpiry: disabled stale IOCs", "count", n)
		}
		time.Sleep(24 * time.Hour)
	}
}
