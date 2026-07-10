package services

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"

	"github.com/minio/minio-go/v7"

	"xcloak-platform/repositories"
)

const auditExportBatchSize = 1000

// auditExportRetentionDays controls how long an exported batch is locked
// against deletion/modification (GOVERNANCE mode — see InitMinIO). Defaults
// to 1 year, the minimum retention window most SOC2/ISO27001 audits expect.
func auditExportRetentionDays() int {
	if v, err := strconv.Atoi(os.Getenv("AUDIT_EXPORT_RETENTION_DAYS")); err == nil && v > 0 {
		return v
	}
	return 365
}

// ExportAuditBatch exports up to auditExportBatchSize new audit_logs rows
// (those after the last exported cursor) to MinIO as a single JSONL object
// under Object Lock retention, then advances the cursor. No-ops if there's
// nothing new or MinIO isn't configured. Returns the number of rows exported.
func ExportAuditBatch() (int, error) {
	if minioClient == nil {
		return 0, nil
	}

	cursor, err := repositories.GetAuditExportCursor()
	if err != nil {
		return 0, fmt.Errorf("reading export cursor: %w", err)
	}

	logs, err := repositories.GetAuditLogsAfter(cursor, auditExportBatchSize)
	if err != nil {
		return 0, fmt.Errorf("loading audit logs to export: %w", err)
	}
	if len(logs) == 0 {
		return 0, nil
	}

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, l := range logs {
		if err := enc.Encode(l); err != nil {
			return 0, fmt.Errorf("encoding audit log #%d: %w", l.ID, err)
		}
	}

	firstID, lastID := logs[0].ID, logs[len(logs)-1].ID
	now := time.Now().UTC()
	objectKey := fmt.Sprintf("audit/%04d/%02d/%02d/audit-%012d-%012d-%d.jsonl",
		now.Year(), now.Month(), now.Day(), firstID, lastID, now.UnixNano())

	retainUntil := now.AddDate(0, 0, auditExportRetentionDays())

	_, err = minioClient.PutObject(context.Background(), auditBucket, objectKey,
		bytes.NewReader(buf.Bytes()), int64(buf.Len()),
		minio.PutObjectOptions{
			ContentType:     "application/x-ndjson",
			Mode:            minio.Governance,
			RetainUntilDate: retainUntil,
		},
	)
	if err != nil {
		return 0, fmt.Errorf("uploading audit export object: %w", err)
	}

	if err := repositories.UpdateAuditExportCursor(lastID, objectKey); err != nil {
		return 0, fmt.Errorf("advancing export cursor (object %q already written — will retry and skip duplicates next run): %w", objectKey, err)
	}

	slog.Info("audit-export: batch exported",
		"rows", len(logs), "first_id", firstID, "last_id", lastID,
		"object", objectKey, "locked_until", retainUntil.Format(time.RFC3339))

	return len(logs), nil
}

// StartAuditExportScheduler runs ExportAuditBatch every 5 minutes. Call as
// a goroutine from main after InitMinIO.
func StartAuditExportScheduler() {
	for {
		WithSingletonLock("audit_export", func() {
			if _, err := ExportAuditBatch(); err != nil {
				slog.Error("audit-export: batch failed", "err", err)
			}
		})
		time.Sleep(5 * time.Minute)
	}
}
