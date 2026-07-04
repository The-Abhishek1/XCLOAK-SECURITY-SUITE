package repositories

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"xcloak-ngfw/database"
	"xcloak-ngfw/models"
)

type IOCPage struct {
	Data  []models.IOC `json:"data"`
	Total int          `json:"total"`
	Page  int          `json:"page"`
	Limit int          `json:"limit"`
}

func GetIOCsPaged(tenantID, page, limit int, search, iocType string) (IOCPage, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * limit

	where := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}
	i := 2

	if iocType != "" && iocType != "all" {
		where += fmt.Sprintf(" AND type = $%d", i)
		args = append(args, iocType)
		i++
	}
	if search != "" {
		where += fmt.Sprintf(" AND (indicator ILIKE $%d OR description ILIKE $%d)", i, i)
		args = append(args, "%"+strings.TrimSpace(search)+"%")
		i++
	}

	var total int
	if err := database.DB.QueryRow(`SELECT COUNT(*) FROM iocs `+where, args...).Scan(&total); err != nil {
		return IOCPage{}, err
	}

	rows, err := queryIOCs(fmt.Sprintf(`
		SELECT id, indicator, type, severity, description, enabled, tenant_id, created_at
		FROM iocs %s
		ORDER BY id DESC
		LIMIT $%d OFFSET $%d
	`, where, i, i+1), append(args, limit, offset)...)
	if err != nil {
		return IOCPage{}, err
	}

	return IOCPage{Data: rows, Total: total, Page: page, Limit: limit}, nil
}

// ErrIOCNotFound is returned by tenant-scoped mutations below when no row
// matches id+tenantID — covers both a nonexistent id and a real id
// belonging to another tenant.
var ErrIOCNotFound = errors.New("ioc not found")

func CreateIOC(
	ioc models.IOC,
	tenantID int,
) error {

	if IOCExists(
		ioc.Indicator,
		ioc.Type,
		tenantID,
	) {

		return nil
	}

	return database.WithTenantTx(context.Background(), tenantID, func(tx *sql.Tx) error {
		_, err := tx.Exec(`
			INSERT INTO iocs
			(
				indicator,
				type,
				severity,
				description,
				enabled,
				tenant_id
			)
			VALUES ($1,$2,$3,$4,$5,$6)
		`,
			ioc.Indicator,
			ioc.Type,
			ioc.Severity,
			ioc.Description,
			ioc.Enabled,
			tenantID,
		)
		return err
	})
}

// GetIOCs returns IOCs belonging to tenantID only. Use this from
// user-facing API paths that have a real tenant context from the request.
func GetIOCs(tenantID int) ([]models.IOC, error) {
	return queryIOCs(`
		SELECT id, indicator, type, severity, description, enabled, tenant_id, created_at
		FROM iocs
		WHERE tenant_id = $1
		ORDER BY id DESC
	`, tenantID)
}

// GetAllIOCs returns every IOC across every tenant. For internal background
// jobs (compliance summary/scoring) with no per-request tenant context —
// not for user-facing API responses, which must use GetIOCs(tenantID).
func GetAllIOCs() ([]models.IOC, error) {
	return queryIOCs(`
		SELECT id, indicator, type, severity, description, enabled, tenant_id, created_at
		FROM iocs
		ORDER BY id DESC
	`)
}

// GetEnabledIOCsForAgent returns enabled IOCs for the tenant that owns
// agentID — used by the connection/file-hash matching engines, which only
// have an agent_id to work from (no per-request tenant context).
func GetEnabledIOCsForAgent(agentID int) ([]models.IOC, error) {
	return queryIOCs(`
		SELECT id, indicator, type, severity, description, enabled, tenant_id, created_at
		FROM iocs
		WHERE enabled = true
		  AND tenant_id = (SELECT tenant_id FROM agents WHERE id = $1)
	`, agentID)
}

func queryIOCs(query string, args ...interface{}) ([]models.IOC, error) {

	rows, err := database.DB.Query(query, args...)

	if err != nil {
		return nil, err
	}

	defer rows.Close()

	var iocs []models.IOC

	for rows.Next() {

		var ioc models.IOC

		err := rows.Scan(
			&ioc.ID,
			&ioc.Indicator,
			&ioc.Type,
			&ioc.Severity,
			&ioc.Description,
			&ioc.Enabled,
			&ioc.TenantID,
			&ioc.CreatedAt,
		)

		if err != nil {
			continue
		}

		iocs = append(iocs, ioc)
	}

	return iocs, nil
}

// GetIOCByID fetches a single IOC, scoped to tenantID — a request for
// another tenant's IOC gets the same "not found" as a nonexistent one.
func GetIOCByID(
	id string,
	tenantID int,
) (*models.IOC, error) {

	var ioc models.IOC

	err := database.DB.QueryRow(`
		SELECT
			id,
			indicator,
			type,
			severity,
			description,
			enabled,
			tenant_id,
			created_at
		FROM iocs
		WHERE id = $1 AND tenant_id = $2
	`,
		id,
		tenantID,
	).Scan(
		&ioc.ID,
		&ioc.Indicator,
		&ioc.Type,
		&ioc.Severity,
		&ioc.Description,
		&ioc.Enabled,
		&ioc.TenantID,
		&ioc.CreatedAt,
	)

	if err != nil {
		return nil, err
	}

	return &ioc, nil
}

func UpdateIOC(
	id string,
	ioc models.IOC,
	tenantID int,
) error {

	tag, err := database.DB.Exec(`
		UPDATE iocs
		SET
			indicator = $1,
			type = $2,
			severity = $3,
			description = $4,
			enabled = $5
		WHERE id = $6 AND tenant_id = $7
	`,
		ioc.Indicator,
		ioc.Type,
		ioc.Severity,
		ioc.Description,
		ioc.Enabled,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrIOCNotFound
	}
	return nil
}

func DeleteIOC(
	id string,
	tenantID int,
) error {

	tag, err := database.DB.Exec(`
		DELETE FROM iocs
		WHERE id = $1 AND tenant_id = $2
	`,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrIOCNotFound
	}
	return nil
}

func EnableIOC(
	id string,
	tenantID int,
) error {

	tag, err := database.DB.Exec(`
		UPDATE iocs
		SET enabled = true
		WHERE id = $1 AND tenant_id = $2
	`,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrIOCNotFound
	}
	return nil
}

func DisableIOC(
	id string,
	tenantID int,
) error {

	tag, err := database.DB.Exec(`
		UPDATE iocs
		SET enabled = false
		WHERE id = $1 AND tenant_id = $2
	`,
		id,
		tenantID,
	)
	if err != nil {
		return err
	}
	if n, _ := tag.RowsAffected(); n == 0 {
		return ErrIOCNotFound
	}
	return nil
}

// IOCExists checks for a duplicate within tenantID only — the same
// indicator can exist independently in multiple tenants.
func IOCExists(
	indicator string,
	iocType string,
	tenantID int,
) bool {

	var count int

	err := database.DB.QueryRow(`
		SELECT COUNT(*)
		FROM iocs
		WHERE
			indicator = $1
			AND type = $2
			AND tenant_id = $3
	`,
		indicator,
		iocType,
		tenantID,
	).Scan(&count)

	if err != nil {
		return false
	}

	return count > 0
}
