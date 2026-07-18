package services

import (
	"log"
	"time"

	"xcloak-platform/database"
)

const itdrInterval = 15 * time.Minute

// StartITDRScheduler runs the ITDR analysis loop for every active tenant.
// Staggered slightly from other schedulers to avoid DB query pile-ups.
func StartITDRScheduler() {
	go func() {
		time.Sleep(90 * time.Second) // initial delay — let migrations settle
		for {
			if err := runITDRForAllTenants(); err != nil {
				log.Printf("[itdr] scheduler error: %v", err)
			}
			time.Sleep(itdrInterval)
		}
	}()
}

func runITDRForAllTenants() error {
	rows, err := database.DB.Query(`SELECT id FROM tenants WHERE is_active = TRUE`)
	if err != nil {
		return err
	}
	defer rows.Close()

	tenantIDs := []int{}
	for rows.Next() {
		var id int
		if err := rows.Scan(&id); err != nil {
			continue
		}
		tenantIDs = append(tenantIDs, id)
	}
	if err := rows.Err(); err != nil {
		return err
	}

	for _, tid := range tenantIDs {
		RunITDRAnalysis(tid)
	}
	return nil
}
