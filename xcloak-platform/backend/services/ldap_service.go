package services

// AD/LDAP Identity Enrichment
//
// Enriches security events with Active Directory / LDAP user context:
//   display_name, email, department, title, manager, groups, account status.
//
// Config (stored in integrations table, name='ldap'):
//   url          — ldap://dc.corp.example.com:389 or ldaps://...
//   bind_dn      — CN=svc-xcloak,OU=ServiceAccounts,DC=corp,DC=example,DC=com
//   bind_password — service account password
//   base_dn      — DC=corp,DC=example,DC=com
//   user_filter  — (sAMAccountName=%s)   [optional, defaults to this]
//   username_attr — sAMAccountName        [optional, defaults to this]
//
// The identity_cache table is checked first (5-minute TTL). On a miss the
// LDAP server is queried directly. Background refresh runs every 30 minutes
// to keep the cache warm for frequently-seen usernames.

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"xcloak-platform/database"
)

// IdentityRecord is one enriched user record.
type IdentityRecord struct {
	Username      string    `json:"username"`
	DisplayName   string    `json:"display_name"`
	Email         string    `json:"email"`
	Department    string    `json:"department"`
	Title         string    `json:"title"`
	Manager       string    `json:"manager"`
	Groups        []string  `json:"groups"`
	AccountStatus string    `json:"account_status"` // active | disabled | locked | unknown
	LastLogon     time.Time `json:"last_logon,omitempty"`
	CachedAt      time.Time `json:"cached_at"`
}

// in-memory hotspot cache: tenantID+username → record+expiry.
type cacheEntry struct {
	rec    IdentityRecord
	expiry time.Time
}

var (
	identCache   sync.Map // key: "tenantID:username"
	identCacheTTL = 5 * time.Minute
)

// ldapConfig holds the parsed integration config for one tenant.
type ldapConfig struct {
	URL          string `json:"url"`
	BindDN       string `json:"bind_dn"`
	BindPassword string `json:"bind_password"`
	BaseDN       string `json:"base_dn"`
	UserFilter   string `json:"user_filter"`   // e.g. (sAMAccountName=%s)
	UsernameAttr string `json:"username_attr"` // e.g. sAMAccountName
}

// StartLDAPCacheRefresh periodically re-queries LDAP for already-cached
// usernames so alerts stay enriched without cold-cache latency.
func StartLDAPCacheRefresh() {
	go func() {
		for {
			time.Sleep(30 * time.Minute)
			refreshLDAPCache()
		}
	}()
}

func refreshLDAPCache() {
	rows, err := database.DB.Query(`
		SELECT tenant_id, username FROM identity_cache
		WHERE cached_at < NOW() - INTERVAL '25 minutes'
		LIMIT 500
	`)
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var tenantID int
		var username string
		if rows.Scan(&tenantID, &username) == nil {
			LookupIdentity(username, tenantID) //nolint:errcheck
		}
	}
}

// LookupIdentity returns enriched identity for username in tenantID.
// Returns the record and true on hit; false if LDAP is unconfigured or lookup fails.
func LookupIdentity(username string, tenantID int) (IdentityRecord, bool) {
	if username == "" {
		return IdentityRecord{}, false
	}

	// 1. In-memory hotspot cache
	key := fmt.Sprintf("%d:%s", tenantID, strings.ToLower(username))
	if v, ok := identCache.Load(key); ok {
		if e := v.(cacheEntry); time.Now().Before(e.expiry) {
			return e.rec, true
		}
	}

	// 2. DB cache
	var rec IdentityRecord
	var groupsRaw string
	var cachedAt time.Time
	var lastLogon *time.Time
	err := database.DB.QueryRow(`
		SELECT username, COALESCE(display_name,''), COALESCE(email,''),
		       COALESCE(department,''), COALESCE(title,''), COALESCE(manager,''),
		       COALESCE(groups::text,'{}'), account_status, last_logon, cached_at
		FROM identity_cache
		WHERE tenant_id = $1 AND username = $2
	`, tenantID, strings.ToLower(username)).Scan(
		&rec.Username, &rec.DisplayName, &rec.Email,
		&rec.Department, &rec.Title, &rec.Manager,
		&groupsRaw, &rec.AccountStatus,
		&lastLogon, &cachedAt,
	)
	if err == nil && time.Since(cachedAt) < identCacheTTL {
		rec.Groups = parseLDAPGroups(groupsRaw)
		if lastLogon != nil {
			rec.LastLogon = *lastLogon
		}
		rec.CachedAt = cachedAt
		identCache.Store(key, cacheEntry{rec: rec, expiry: time.Now().Add(identCacheTTL)})
		return rec, true
	}

	// 3. Live LDAP query
	cfg, ok := loadLDAPConfig(tenantID)
	if !ok {
		return IdentityRecord{}, false
	}
	rec, err = queryLDAP(cfg, username)
	if err != nil {
		log.Printf("[LDAP] lookup failed tenant=%d user=%s: %v", tenantID, username, err)
		return IdentityRecord{}, false
	}

	// Persist to DB cache
	saveLDAPRecord(rec, tenantID)

	identCache.Store(key, cacheEntry{rec: rec, expiry: time.Now().Add(identCacheTTL)})
	return rec, true
}

// EnrichAlertMessage appends identity context to an alert's log message.
func EnrichAlertMessage(logMessage, username string, tenantID int) string {
	rec, ok := LookupIdentity(username, tenantID)
	if !ok {
		return logMessage
	}
	parts := []string{}
	if rec.DisplayName != "" { parts = append(parts, "User: "+rec.DisplayName) }
	if rec.Department  != "" { parts = append(parts, "Dept: "+rec.Department) }
	if rec.Title       != "" { parts = append(parts, "Title: "+rec.Title) }
	if rec.AccountStatus != "" && rec.AccountStatus != "active" {
		parts = append(parts, "Account: "+rec.AccountStatus)
	}
	if len(parts) == 0 {
		return logMessage
	}
	return logMessage + " [Identity: " + strings.Join(parts, ", ") + "]"
}

// ── LDAP query ────────────────────────────────────────────────────────────────

func queryLDAP(cfg ldapConfig, username string) (IdentityRecord, error) {
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return IdentityRecord{}, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return IdentityRecord{}, fmt.Errorf("bind: %w", err)
	}

	filter := cfg.UserFilter
	if filter == "" {
		filter = "(sAMAccountName=%s)"
	}
	filter = fmt.Sprintf(filter, ldap.EscapeFilter(username))

	req := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1, 10, false,
		filter,
		[]string{
			"sAMAccountName", "displayName", "mail",
			"department", "title", "manager",
			"memberOf", "userAccountControl",
			"lastLogonTimestamp",
		},
		nil,
	)

	sr, err := conn.Search(req)
	if err != nil {
		return IdentityRecord{}, fmt.Errorf("search: %w", err)
	}
	if len(sr.Entries) == 0 {
		return IdentityRecord{}, fmt.Errorf("user not found: %s", username)
	}

	e := sr.Entries[0]
	rec := IdentityRecord{
		Username:    strings.ToLower(username),
		DisplayName: e.GetAttributeValue("displayName"),
		Email:       e.GetAttributeValue("mail"),
		Department:  e.GetAttributeValue("department"),
		Title:       e.GetAttributeValue("title"),
		Manager:     managerCN(e.GetAttributeValue("manager")),
		Groups:      memberOfCNs(e.GetAttributeValues("memberOf")),
		CachedAt:    time.Now(),
	}

	// userAccountControl flags: 2=disabled, 16=locked
	uac := e.GetAttributeValue("userAccountControl")
	rec.AccountStatus = parseUAC(uac)

	return rec, nil
}

func loadLDAPConfig(tenantID int) (ldapConfig, bool) {
	var configJSON []byte
	var enabled bool
	err := database.DB.QueryRow(`
		SELECT enabled, config FROM integrations
		WHERE name = 'ldap' AND tenant_id = $1
	`, tenantID).Scan(&enabled, &configJSON)
	if err != nil || !enabled || len(configJSON) == 0 {
		return ldapConfig{}, false
	}
	var cfg ldapConfig
	if err := json.Unmarshal(configJSON, &cfg); err != nil || cfg.URL == "" {
		return ldapConfig{}, false
	}
	return cfg, true
}

func saveLDAPRecord(rec IdentityRecord, tenantID int) {
	groups := "{}"
	if len(rec.Groups) > 0 {
		quoted := make([]string, len(rec.Groups))
		for i, g := range rec.Groups {
			quoted[i] = `"` + strings.ReplaceAll(g, `"`, `\"`) + `"`
		}
		groups = "{" + strings.Join(quoted, ",") + "}"
	}

	var lastLogon *time.Time
	if !rec.LastLogon.IsZero() {
		lastLogon = &rec.LastLogon
	}

	database.DB.Exec(`
		INSERT INTO identity_cache
		  (tenant_id, username, display_name, email, department, title, manager,
		   groups, account_status, last_logon, cached_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::text[],$9,$10,NOW())
		ON CONFLICT (tenant_id, username) DO UPDATE SET
		  display_name   = EXCLUDED.display_name,
		  email          = EXCLUDED.email,
		  department     = EXCLUDED.department,
		  title          = EXCLUDED.title,
		  manager        = EXCLUDED.manager,
		  groups         = EXCLUDED.groups,
		  account_status = EXCLUDED.account_status,
		  last_logon     = EXCLUDED.last_logon,
		  cached_at      = NOW()
	`, tenantID, rec.Username, rec.DisplayName, rec.Email,
		rec.Department, rec.Title, rec.Manager,
		groups, rec.AccountStatus, lastLogon)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// managerCN extracts the CN from a DN like
// "CN=Jane Smith,OU=Management,DC=corp,DC=com" → "Jane Smith"
func managerCN(dn string) string {
	parts := strings.SplitN(dn, ",", 2)
	if len(parts) == 0 {
		return dn
	}
	cn := strings.TrimPrefix(parts[0], "CN=")
	return cn
}

func memberOfCNs(dns []string) []string {
	var out []string
	for _, dn := range dns {
		out = append(out, managerCN(dn))
	}
	return out
}

func parseUAC(uac string) string {
	var n int
	fmt.Sscan(uac, &n)
	if n == 0 {
		return "unknown"
	}
	if n&2 != 0 {
		return "disabled"
	}
	if n&16 != 0 {
		return "locked"
	}
	return "active"
}

// parseLDAPGroups converts a PostgreSQL text[] literal "{a,b}" to []string.
func parseLDAPGroups(s string) []string {
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	if s == "" {
		return []string{}
	}
	var parts []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		p = strings.Trim(p, `"`)
		parts = append(parts, p)
	}
	return parts
}
