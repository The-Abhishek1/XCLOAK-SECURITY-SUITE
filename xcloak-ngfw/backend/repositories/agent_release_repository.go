package repositories

import (
	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

// PublishAgentRelease upserts the current release for a platform — one row
// per platform, republishing replaces it rather than accumulating history.
func PublishAgentRelease(r models.AgentRelease) (*models.AgentRelease, error) {
	err := database.DB.QueryRow(`
		INSERT INTO agent_releases
			(platform, version, sha256, signature, public_key_fingerprint, download_url, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		ON CONFLICT (platform) DO UPDATE SET
			version               = EXCLUDED.version,
			sha256                = EXCLUDED.sha256,
			signature             = EXCLUDED.signature,
			public_key_fingerprint = EXCLUDED.public_key_fingerprint,
			download_url          = EXCLUDED.download_url,
			created_by            = EXCLUDED.created_by,
			created_at            = now()
		RETURNING id, created_at
	`, r.Platform, r.Version, r.SHA256, r.Signature, r.PublicKeyFingerprint,
		r.DownloadURL, r.CreatedBy).Scan(&r.ID, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}

// GetAgentReleases returns every platform's current release.
func GetAgentReleases() ([]models.AgentRelease, error) {
	rows, err := database.DB.Query(`
		SELECT id, platform, version, sha256,
		       COALESCE(signature,''), COALESCE(public_key_fingerprint,''),
		       download_url, created_by, created_at
		FROM agent_releases ORDER BY platform
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []models.AgentRelease
	for rows.Next() {
		var r models.AgentRelease
		if err := rows.Scan(&r.ID, &r.Platform, &r.Version, &r.SHA256,
			&r.Signature, &r.PublicKeyFingerprint,
			&r.DownloadURL, &r.CreatedBy, &r.CreatedAt); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

// GetAgentReleaseByPlatform is what an agent itself calls to check for an
// update — returns nil, sql.ErrNoRows (via the caller's err check) if
// nothing has been published for that platform yet.
func GetAgentReleaseByPlatform(platform string) (*models.AgentRelease, error) {
	var r models.AgentRelease
	err := database.DB.QueryRow(`
		SELECT id, platform, version, sha256,
		       COALESCE(signature,''), COALESCE(public_key_fingerprint,''),
		       download_url, created_by, created_at
		FROM agent_releases WHERE platform = $1
	`, platform).Scan(&r.ID, &r.Platform, &r.Version, &r.SHA256,
		&r.Signature, &r.PublicKeyFingerprint,
		&r.DownloadURL, &r.CreatedBy, &r.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &r, nil
}
