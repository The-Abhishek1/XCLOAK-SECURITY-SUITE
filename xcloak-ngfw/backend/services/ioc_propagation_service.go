package services

// Cross-tenant IOC propagation — the "network effect" gap vs commercial vendors.
//
// When a tenant marks an IOC as shareable=true (opt-in per IOC), a background
// goroutine copies it to all other tenants that have opted into ioc_sharing_enabled.
// Propagated IOCs are:
//   - stripped of source and description (keeps tenant provenance private)
//   - marked platform_ioc=true and source='xcloak-platform'
//   - deduplicated via ioc_propagations to avoid re-inserting on every cycle
//
// Propagation runs every 5 minutes. Only high/critical IOCs are propagated to
// avoid polluting tenants with low-confidence indicators.

import (
	"log"
	"time"

	"xcloak-ngfw/database"
)

const (
	propagationInterval  = 5 * time.Minute
	minShareableSeverity = "high" // only "high" and "critical" are propagated
)

// StartIOCPropagation runs the cross-tenant IOC sharing loop in a goroutine.
// It must be called once at startup after the database is connected.
func StartIOCPropagation() {
	go func() {
		for {
			if err := runPropagationCycle(); err != nil {
				log.Printf("[ioc-propagation] cycle error: %v", err)
			}
			time.Sleep(propagationInterval)
		}
	}()
}

// runPropagationCycle performs one full propagation pass.
func runPropagationCycle() error {
	// 1. Collect shareable high/critical IOCs from all tenants.
	rows, err := database.DB.Query(`
		SELECT i.id, i.tenant_id, i.indicator, i.type, i.severity
		FROM iocs i
		JOIN tenants t ON t.id = i.tenant_id
		WHERE i.shareable   = TRUE
		  AND i.enabled     = TRUE
		  AND i.severity    IN ('high', 'critical')
		ORDER BY i.created_at DESC
		LIMIT 500
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	type shareableIOC struct {
		id        int
		tenantID  int
		indicator string
		iocType   string
		severity  string
	}
	var iocs []shareableIOC
	for rows.Next() {
		var s shareableIOC
		if err := rows.Scan(&s.id, &s.tenantID, &s.indicator, &s.iocType, &s.severity); err != nil {
			continue
		}
		iocs = append(iocs, s)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(iocs) == 0 {
		return nil
	}

	// 2. Collect all opted-in tenant IDs.
	destRows, err := database.DB.Query(`SELECT id FROM tenants WHERE ioc_sharing_enabled = TRUE`)
	if err != nil {
		return err
	}
	defer destRows.Close()

	var destTenants []int
	for destRows.Next() {
		var id int
		if err := destRows.Scan(&id); err != nil {
			continue
		}
		destTenants = append(destTenants, id)
	}
	if err := destRows.Err(); err != nil {
		return err
	}
	if len(destTenants) == 0 {
		return nil
	}

	// 3. Propagate each IOC to each eligible destination tenant (skip source tenant).
	propagated := 0
	for _, ioc := range iocs {
		for _, dest := range destTenants {
			if dest == ioc.tenantID {
				continue
			}
			if err := propagateOne(ioc.tenantID, dest, ioc.indicator, ioc.iocType, ioc.severity); err != nil {
				log.Printf("[ioc-propagation] skip %s→tenant%d %s: %v",
					ioc.indicator, dest, ioc.iocType, err)
				continue
			}
			propagated++
		}
	}
	if propagated > 0 {
		log.Printf("[ioc-propagation] propagated %d IOC×tenant pairs", propagated)
	}
	return nil
}

// propagateOne inserts one IOC into a destination tenant if not already present,
// then records the propagation to prevent duplicates on future cycles.
func propagateOne(sourceTenant, destTenant int, indicator, iocType, severity string) error {
	// Idempotency check — skip if this (source, dest, indicator) triple already propagated.
	var existing int
	err := database.DB.QueryRow(`
		SELECT COUNT(*) FROM ioc_propagations
		WHERE source_tenant = $1 AND dest_tenant = $2 AND indicator = $3
	`, sourceTenant, destTenant, indicator).Scan(&existing)
	if err != nil {
		return err
	}
	if existing > 0 {
		return nil // already done
	}

	// Upsert the IOC into the destination tenant's iocs table.
	// We do NOT overwrite an existing IOC in that tenant if they already have it
	// (the tenant's own version may have better context).
	_, err = database.DB.Exec(`
		INSERT INTO iocs (indicator, type, severity, description, enabled,
		                  tenant_id, source, shareable, platform_ioc)
		VALUES ($1, $2, $3, 'Propagated via XCloak platform threat sharing', TRUE,
		        $4, 'xcloak-platform', FALSE, TRUE)
		ON CONFLICT DO NOTHING
	`, indicator, iocType, severity, destTenant)
	if err != nil {
		return err
	}

	// Record the propagation so we don't insert again on the next cycle.
	_, err = database.DB.Exec(`
		INSERT INTO ioc_propagations (source_tenant, dest_tenant, indicator, ioc_type, severity)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT DO NOTHING
	`, sourceTenant, destTenant, indicator, iocType, severity)
	return err
}

// MarkIOCShareable sets shareable=true on an IOC. Called from the IOC management
// API when a tenant analyst explicitly shares an indicator with the platform.
func MarkIOCShareable(iocID, tenantID int, shareable bool) error {
	_, err := database.DB.Exec(`
		UPDATE iocs SET shareable = $1
		WHERE id = $2 AND tenant_id = $3
	`, shareable, iocID, tenantID)
	return err
}

// SetTenantIOCSharingEnabled toggles a tenant's participation in platform IOC sharing.
func SetTenantIOCSharingEnabled(tenantID int, enabled bool) error {
	_, err := database.DB.Exec(`
		UPDATE tenants SET ioc_sharing_enabled = $1 WHERE id = $2
	`, enabled, tenantID)
	return err
}
