package services

import (
	"fmt"
	"testing"
	"time"
)

// partitionNameFor returns the expected partition table name for a given month.
// Mirrors the naming logic in EnsureEndpointLogPartitions.
func partitionNameFor(t time.Time) string {
	return fmt.Sprintf("%s_%04d_%02d", partitionTable, t.Year(), int(t.Month()))
}

func TestPartitionNaming(t *testing.T) {
	cases := []struct {
		year, month int
		want        string
	}{
		{2026, 1, "endpoint_logs_2026_01"},
		{2026, 7, "endpoint_logs_2026_07"},
		{2026, 12, "endpoint_logs_2026_12"},
		{2027, 1, "endpoint_logs_2027_01"},
	}
	for _, c := range cases {
		got := partitionNameFor(time.Date(c.year, time.Month(c.month), 15, 0, 0, 0, 0, time.UTC))
		if got != c.want {
			t.Errorf("partitionNameFor(%d-%02d) = %q, want %q", c.year, c.month, got, c.want)
		}
	}
}

func TestPartitionMonthBounds(t *testing.T) {
	// Verify that the month boundaries are correctly computed for year-end rollover.
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)

	for i := 0; i <= partitionMonthsAhead; i++ {
		target := now.AddDate(0, i, 0)
		monthStart := time.Date(target.Year(), target.Month(), 1, 0, 0, 0, 0, time.UTC)
		monthEnd := monthStart.AddDate(0, 1, 0)

		// monthEnd must be after monthStart
		if !monthEnd.After(monthStart) {
			t.Errorf("month %d: end %v is not after start %v", i, monthEnd, monthStart)
		}

		// monthEnd must be the 1st of the following month
		if monthEnd.Day() != 1 {
			t.Errorf("month %d: end day = %d, want 1", i, monthEnd.Day())
		}

		// No overlap — one month's end is the next month's start
		if i > 0 {
			prev := now.AddDate(0, i-1, 0)
			prevEnd := time.Date(prev.Year(), prev.Month()+1, 1, 0, 0, 0, 0, time.UTC)
			if !prevEnd.Equal(monthStart) {
				t.Errorf("month %d: gap or overlap between partitions: prevEnd=%v monthStart=%v",
					i, prevEnd, monthStart)
			}
		}
	}
}

func TestPartitionYearRollover(t *testing.T) {
	// Starting in November, monthsAhead=3 should reach February of the next year.
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	last := now.AddDate(0, partitionMonthsAhead, 0)

	if last.Year() != 2027 {
		t.Errorf("expected year 2027 for last partition, got %d", last.Year())
	}
	if last.Month() != time.February {
		t.Errorf("expected February for last partition, got %s", last.Month())
	}

	name := partitionNameFor(last)
	if name != "endpoint_logs_2027_02" {
		t.Errorf("unexpected partition name %q", name)
	}
}
