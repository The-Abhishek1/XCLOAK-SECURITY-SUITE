package repositories

import "xcloak-platform/database"

// GetIncidentIDByFingerprint returns the ID of the most recent incident
// matching the given fingerprint (used by CorrelateAlert to add timeline
// events when a duplicate alert fires but the incident is already open).
func GetIncidentIDByFingerprint(fingerprint string) (int, error) {

	var id int

	err := database.DB.QueryRow(`
		SELECT id FROM incidents
		WHERE fingerprint = $1
		ORDER BY created_at DESC
		LIMIT 1
	`, fingerprint).Scan(&id)

	if err != nil {
		return 0, err
	}

	return id, nil
}
