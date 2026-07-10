package services

import (
	"errors"
	"fmt"

	"xcloak-platform/models"
	"xcloak-platform/repositories"
)

// AllPermissions is the fixed permission taxonomy, derived 1:1 from the
// admin-gated route groups in routes.go — not DB-defined, since each key
// maps to a real, fixed set of code paths. The frontend renders its
// checkbox UI from this list (via GetPermissionsHandler) rather than
// hardcoding it a second time.
var AllPermissions = []string{
	"manage_firewall",
	"manage_agents",
	"approve_soar_actions",
	"manage_detection_rules",
	"manage_threat_intel",
	"manage_playbooks",
	"manage_suppression",
	"manage_compliance",
	"export_audit_logs",
	"manage_users",
	"manage_api_keys",
	"manage_integrations",
	"run_ai_analysis",
	"manage_scheduler",
	"manage_correlation_rules",
	"manage_quarantine",
	"run_scripts",
	"sync_firewall",
	"manage_notifications",
}

var builtinRoles = map[string]bool{"admin": true, "analyst": true, "viewer": true}

func isValidPermission(p string) bool {
	for _, ap := range AllPermissions {
		if ap == p {
			return true
		}
	}
	return false
}

// IsValidRole reports whether role is one of the built-in roles OR an
// existing custom role for tenantID — the shared check InviteUser,
// UpdateUserRole, and CreateAPIKey all use instead of each hardcoding their
// own admin/analyst/viewer-only map.
func IsValidRole(role string, tenantID int) bool {
	if builtinRoles[role] {
		return true
	}
	_, err := repositories.GetCustomRoleByName(tenantID, role)
	return err == nil
}

func CreateCustomRole(tenantID int, name string, permissions []string, createdBy string) (*models.CustomRole, error) {

	if name == "" {
		return nil, errors.New("name is required")
	}
	if builtinRoles[name] {
		return nil, errors.New("name collides with a built-in role (admin/analyst/viewer)")
	}
	for _, p := range permissions {
		if !isValidPermission(p) {
			return nil, fmt.Errorf("unknown permission: %s", p)
		}
	}

	role, err := repositories.CreateCustomRole(tenantID, name, permissions, createdBy)
	if err != nil {
		return nil, err
	}

	LogEvent("CREATE_CUSTOM_ROLE", fmt.Sprintf("%s (%d permissions)", name, len(permissions)), createdBy)
	return role, nil
}

func GetCustomRoles(tenantID int) ([]models.CustomRole, error) {
	return repositories.GetCustomRolesByTenant(tenantID)
}

func UpdateCustomRole(id, tenantID int, permissions []string, updatedBy string) error {
	for _, p := range permissions {
		if !isValidPermission(p) {
			return fmt.Errorf("unknown permission: %s", p)
		}
	}
	if err := repositories.UpdateCustomRole(id, tenantID, permissions); err != nil {
		return err
	}
	LogEvent("UPDATE_CUSTOM_ROLE", fmt.Sprintf("role id %d", id), updatedBy)
	return nil
}

func DeleteCustomRole(id, tenantID int, deletedBy string) error {
	if err := repositories.DeleteCustomRole(id, tenantID); err != nil {
		return err
	}
	LogEvent("DELETE_CUSTOM_ROLE", fmt.Sprintf("role id %d", id), deletedBy)
	return nil
}

// HasPermission is what middleware.RequirePermission calls — admin always
// has every permission (unchanged superuser behavior); analyst/viewer never
// match a custom role so they get exactly today's behavior (denied), same
// as before this feature existed.
func HasPermission(role string, tenantID int, perm string) bool {
	if role == "admin" {
		return true
	}
	custom, err := repositories.GetCustomRoleByName(tenantID, role)
	if err != nil {
		return false
	}
	for _, p := range custom.Permissions {
		if p == perm {
			return true
		}
	}
	return false
}
