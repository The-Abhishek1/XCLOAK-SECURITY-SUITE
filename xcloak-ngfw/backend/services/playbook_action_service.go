package services

import (
	"errors"

	"xcloak-ngfw/models"
	"xcloak-ngfw/repositories"
)

// ErrPlaybookNotFoundForAction is returned when action.PlaybookID doesn't
// belong to the caller's tenant.
var ErrPlaybookNotFoundForAction = errors.New("playbook not found")

// CreatePlaybookAction verifies action.PlaybookID belongs to tenantID
// before inserting — otherwise a caller could attach an action (with
// their own tenant_id) to another tenant's playbook_id.
func CreatePlaybookAction(
	action models.PlaybookAction,
	tenantID int,
) error {

	if _, err := repositories.GetPlaybookByID(action.PlaybookID, tenantID); err != nil {
		return ErrPlaybookNotFoundForAction
	}

	return repositories.CreatePlaybookAction(
		action,
		tenantID,
	)
}

func GetPlaybookActions(
	playbookID string,
	tenantID int,
) ([]models.PlaybookAction, error) {

	return repositories.GetPlaybookActionsByPlaybookID(
		playbookID,
		tenantID,
	)
}

func DeletePlaybookAction(
	id string,
	tenantID int,
) error {

	return repositories.DeletePlaybookAction(
		id,
		tenantID,
	)
}
