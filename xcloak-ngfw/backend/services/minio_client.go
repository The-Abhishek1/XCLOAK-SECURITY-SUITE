package services

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

var (
	minioClient *minio.Client
	auditBucket string
)

// InitMinIO connects to the object store used for immutable audit log
// export and ensures the bucket exists with Object Lock enabled. Object
// Lock can only be turned on at bucket creation — it cannot be enabled on
// an existing bucket, so this never tries to "upgrade" one.
func InitMinIO() error {
	endpoint := os.Getenv("MINIO_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:9000"
	}
	accessKey := os.Getenv("MINIO_ACCESS_KEY")
	secretKey := os.Getenv("MINIO_SECRET_KEY")
	auditBucket = os.Getenv("MINIO_AUDIT_BUCKET")
	if auditBucket == "" {
		auditBucket = "xcloak-audit-log"
	}
	useSSL, _ := strconv.ParseBool(os.Getenv("MINIO_USE_SSL"))

	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return fmt.Errorf("creating minio client: %w", err)
	}
	minioClient = client

	ctx := context.Background()
	exists, err := client.BucketExists(ctx, auditBucket)
	if err != nil {
		return fmt.Errorf("checking audit bucket: %w", err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, auditBucket, minio.MakeBucketOptions{ObjectLocking: true}); err != nil {
			return fmt.Errorf("creating audit bucket with object lock: %w", err)
		}
		slog.Info("minio: created audit bucket with Object Lock", "bucket", auditBucket)
	}

	slog.Info("minio: connected", "endpoint", endpoint, "audit_bucket", auditBucket)
	return nil
}
