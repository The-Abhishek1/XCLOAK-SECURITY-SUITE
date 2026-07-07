package services

import "xcloak-ngfw/repositories"

func LogEvent(
	action string,
	details string,
	username string,
) {
	_ = repositories.CreateAuditLog(action, details, username)
	go PublishAuditEvent(action, details, username)
}
