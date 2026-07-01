package models

import (
	"encoding/json"
	"time"
)

// RemediationPlan is a collection of ordered cleanup steps for one incident
// on one agent. Steps are executed in sequence; any failure marks the plan
// as "partial" rather than aborting the remaining steps.
type RemediationPlan struct {
	ID          int        `json:"id"`
	IncidentID  *int       `json:"incident_id,omitempty"`
	TenantID    int        `json:"tenant_id"`
	AgentID     int        `json:"agent_id"`
	Label       string     `json:"label"`
	CreatedBy   string     `json:"created_by"`
	Status      string     `json:"status"`
	Steps       []RemediationStep `json:"steps,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	CompletedAt *time.Time `json:"completed_at,omitempty"`
}

// RemediationStep is one atomic cleanup action within a plan. It maps 1:1 to
// an AgentTask once dispatched; the task result is mirrored back here.
type RemediationStep struct {
	ID          int             `json:"id"`
	PlanID      int             `json:"plan_id"`
	StepOrder   int             `json:"step_order"`
	ActionType  string          `json:"action_type"`
	Payload     json.RawMessage `json:"payload"`
	Status      string          `json:"status"`
	TaskID      *int            `json:"task_id,omitempty"`
	Result      string          `json:"result,omitempty"`
	ExecutedAt  *time.Time      `json:"executed_at,omitempty"`
	CompletedAt *time.Time      `json:"completed_at,omitempty"`
}

// MemoryDumpResult is the JSON the agent sends back as the task result when
// it completes a memory_dump task. StoragePath is the server-local path where
// the dump was written (via the /api/agents/file upload endpoint).
type MemoryDumpResult struct {
	SizeBytes   int64  `json:"size_bytes"`
	SHA256      string `json:"sha256"`
	StoragePath string `json:"storage_path"`
	Process     string `json:"process,omitempty"` // empty = full RAM dump
	PID         int    `json:"pid,omitempty"`
}

// ProcessSnapshotEntry is one row in a process_snapshot artifact. It is richer
// than a standard collect_processes entry: it includes the parent PID, full
// command line, loaded libraries/maps, and open file handles.
type ProcessSnapshotEntry struct {
	PID         int      `json:"pid"`
	PPID        int      `json:"ppid"`
	Name        string   `json:"name"`
	CmdLine     string   `json:"cmdline"`
	User        string   `json:"user"`
	ExePath     string   `json:"exe_path"`
	Hashes      struct {
		MD5    string `json:"md5,omitempty"`
		SHA256 string `json:"sha256,omitempty"`
	} `json:"hashes,omitempty"`
	Modules     []string `json:"modules,omitempty"` // loaded DLLs / shared libs
	OpenFiles   []string `json:"open_files,omitempty"`
	Connections []string `json:"connections,omitempty"` // "proto:src->dst"
	StartTime   string   `json:"start_time,omitempty"`
	CPUPct      float64  `json:"cpu_pct,omitempty"`
	MemRSS      int64    `json:"mem_rss_bytes,omitempty"`
}
