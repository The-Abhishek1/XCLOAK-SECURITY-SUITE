package models

import "time"

type UserRiskProfile struct {
	ID                   int        `json:"id"`
	TenantID             int        `json:"tenant_id"`
	Username             string     `json:"username"`
	Source               string     `json:"source"`
	RiskScore            int        `json:"risk_score"`
	TotalEvents          int        `json:"total_events"`
	FailedLogins         int        `json:"failed_logins"`
	OffHoursEvents       int        `json:"off_hours_events"`
	UniqueIPs            int        `json:"unique_ips"`
	PrivilegeEscalations int        `json:"privilege_escalations"`
	Flags                []string   `json:"flags"`
	LastSeenIP           string     `json:"last_seen_ip"`
	LastEventAt          *time.Time `json:"last_event_at"`
	AnalyzedAt           time.Time  `json:"analyzed_at"`
}

type UEBAEvent struct {
	ID          int       `json:"id"`
	TenantID    int       `json:"tenant_id"`
	Username    string    `json:"username"`
	EventType   string    `json:"event_type"`
	Severity    string    `json:"severity"`
	Description string    `json:"description"`
	SourceIP    string    `json:"source_ip"`
	AgentID     *int      `json:"agent_id,omitempty"`
	RawLog      string    `json:"raw_log,omitempty"`
	DetectedAt  time.Time `json:"detected_at"`
}

type FeedSyncLog struct {
	ID           int       `json:"id"`
	FeedID       int       `json:"feed_id"`
	TenantID     int       `json:"tenant_id"`
	Status       string    `json:"status"`
	IOCsAdded    int       `json:"iocs_added"`
	ErrorMessage string    `json:"error_message,omitempty"`
	SyncedAt     time.Time `json:"synced_at"`
}

type Session struct {
	ID           int       `json:"id"`
	TenantID     int       `json:"tenant_id"`
	UserID       *int      `json:"user_id,omitempty"`
	Username     string    `json:"username"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	TokenHash    string    `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	LastActiveAt time.Time `json:"last_active_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	Revoked      bool      `json:"revoked"`
}

type TenantSecurityPolicy struct {
	TenantID              int       `json:"tenant_id"`
	SessionTimeoutMins    int       `json:"session_timeout_mins"`
	MaxConcurrentSessions int       `json:"max_concurrent_sessions"`
	MFARequired           bool      `json:"mfa_required"`
	UpdatedAt             time.Time `json:"updated_at"`
}
