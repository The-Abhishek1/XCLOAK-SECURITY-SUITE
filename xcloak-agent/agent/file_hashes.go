package agent

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"

	"xcloak-agent/models"
)

// MaxFileSize skips files larger than 50MB to avoid hanging on large binaries
const MaxFileSize = 50 * 1024 * 1024

// ScanTargets are the directories scanned on every collect_file_hashes task.
// Covers common malware drop locations on Linux.
var ScanTargets = []string{
	"/bin",
	"/usr/bin",
	"/usr/local/bin",
	"/sbin",
	"/usr/sbin",
	"/tmp",
	"/var/tmp",
	"/dev/shm",
}

func CollectFileHashes(agentID int) []models.FileHash {

	var hashes []models.FileHash

	for _, target := range ScanTargets {

		filepath.Walk(
			target,
			func(path string, info os.FileInfo, err error) error {

				if err != nil {
					return nil
				}

				if info.IsDir() {
					return nil
				}

				// Skip files that are too large
				if info.Size() > MaxFileSize {
					return nil
				}

				result, err := hashFile(path)
				if err != nil {
					return nil
				}

				hashes = append(hashes, models.FileHash{
					AgentID:    agentID,
					FilePath:   path,
					MD5Hash:    result.MD5Hash,
					SHA256Hash: result.SHA256Hash,
					FileSize:   info.Size(),
					FileName:   info.Name(),
				})

				return nil
			},
		)
	}

	return hashes
}

type HashResult struct {
	MD5Hash    string
	SHA256Hash string
}

func hashFile(path string) (HashResult, error) {

	file, err := os.Open(path)
	if err != nil {
		return HashResult{}, err
	}
	defer file.Close()

	md5h := md5.New()
	sha := sha256.New()

	// Use TeeReader to hash both in a single pass (more efficient)
	tee := io.TeeReader(file, md5h)
	if _, err := io.Copy(sha, tee); err != nil {
		return HashResult{}, err
	}

	return HashResult{
		MD5Hash:    hex.EncodeToString(md5h.Sum(nil)),
		SHA256Hash: hex.EncodeToString(sha.Sum(nil)),
	}, nil
}
