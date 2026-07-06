package services

import (
	"fmt"
	"time"

	"xcloak-ngfw/database"
)

const (
	partitionTable       = "endpoint_logs"
	partitionMonthsAhead = 3 // keep current + 3 future months pre-created
)

// EnsureEndpointLogPartitions idempotently creates monthly range partitions for
// endpoint_logs for the current month through partitionMonthsAhead months into
// the future.
//
// If a partition already exists (CREATE TABLE IF NOT EXISTS), the statement is
// a no-op so this is safe to call on every startup and on every daily tick.
//
// Why daily and not monthly: the partition for month M must exist BEFORE the
// first row of month M is inserted.  If we only ran on the 1st of each month
// and the job failed (DB hiccup, restart), rows would land in the DEFAULT
// partition (endpoint_logs_legacy) and defeat partition pruning for that month.
// Running daily gives 30+ retries before the deadline and keeps the window
// small enough to be invisible in Prometheus.
func EnsureEndpointLogPartitions() {
	now := time.Now().UTC()
	failed := 0

	for i := 0; i <= partitionMonthsAhead; i++ {
		t := now.AddDate(0, i, 0)

		// First instant of the month, last instant is the first of the next.
		monthStart := time.Date(t.Year(), t.Month(), 1, 0, 0, 0, 0, time.UTC)
		monthEnd := monthStart.AddDate(0, 1, 0)

		// Naming convention matches migration 055: endpoint_logs_YYYY_MM
		partName := fmt.Sprintf("%s_%04d_%02d", partitionTable, t.Year(), int(t.Month()))

		// Partition name contains only digits and underscores — safe to embed.
		// IF NOT EXISTS makes this idempotent (PostgreSQL 14+, we target PG 16).
		sql := fmt.Sprintf(
			`CREATE TABLE IF NOT EXISTS %s PARTITION OF %s
			 FOR VALUES FROM ('%s') TO ('%s')`,
			partName,
			partitionTable,
			monthStart.Format("2006-01-02"),
			monthEnd.Format("2006-01-02"),
		)

		if _, err := database.DB.Exec(sql); err != nil {
			fmt.Printf("[partition-manager] failed to ensure %s: %v\n", partName, err)
			failed++
		} else {
			fmt.Printf("[partition-manager] ensured partition %s (%s → %s)\n",
				partName,
				monthStart.Format("2006-01"),
				monthEnd.Format("2006-01"),
			)
		}
	}

	if failed > 0 {
		fmt.Printf("[partition-manager] WARNING: %d partition(s) could not be created — rows for those months will land in the DEFAULT partition\n", failed)
	}
}

// DropOldEndpointLogPartitions drops monthly partitions older than retainMonths.
// The dropped partition and all its rows are permanently deleted — call only
// after verifying that the data has been archived elsewhere if required.
//
// Not called by StartPartitionManager by default; invoke explicitly when you
// have a tested archival pipeline in place.
func DropOldEndpointLogPartitions(retainMonths int) {
	cutoff := time.Now().UTC().AddDate(0, -retainMonths, 0)
	cutoff = time.Date(cutoff.Year(), cutoff.Month(), 1, 0, 0, 0, 0, time.UTC)

	rows, err := database.DB.Query(`
		SELECT c.relname
		FROM   pg_inherits i
		JOIN   pg_class    p ON p.oid = i.inhparent
		JOIN   pg_class    c ON c.oid = i.inhrelid
		WHERE  p.relname = $1
		  AND  c.relname ~ $2
		  AND  c.relname <> $3
	`, partitionTable,
		fmt.Sprintf(`^%s_\d{4}_\d{2}$`, partitionTable),
		partitionTable+"_legacy",
	)
	if err != nil {
		fmt.Printf("[partition-manager] drop scan failed: %v\n", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			continue
		}

		// Parse YYYY_MM suffix.
		var year, month int
		if _, err := fmt.Sscanf(name, partitionTable+"_%04d_%02d", &year, &month); err != nil {
			continue
		}
		partStart := time.Date(year, time.Month(month), 1, 0, 0, 0, 0, time.UTC)
		if partStart.Before(cutoff) {
			if _, err := database.DB.Exec(fmt.Sprintf("DROP TABLE IF EXISTS %s", name)); err != nil {
				fmt.Printf("[partition-manager] failed to drop %s: %v\n", name, err)
			} else {
				fmt.Printf("[partition-manager] dropped old partition %s (before %s)\n", name, cutoff.Format("2006-01"))
			}
		}
	}
}

// StartPartitionManager launches the background partition pre-creation job.
// It runs once at startup (so missing partitions are fixed immediately after a
// deployment) and then daily thereafter.  The singleton advisory lock ensures
// only one replica runs the DDL at a time in a multi-replica deployment.
func StartPartitionManager() {
	go func() {
		WithSingletonLock("partition_manager", EnsureEndpointLogPartitions)

		ticker := time.NewTicker(24 * time.Hour)
		defer ticker.Stop()
		for range ticker.C {
			WithSingletonLock("partition_manager", EnsureEndpointLogPartitions)
		}
	}()
	fmt.Println("Partition manager started (pre-creating endpoint_logs partitions)")
}
