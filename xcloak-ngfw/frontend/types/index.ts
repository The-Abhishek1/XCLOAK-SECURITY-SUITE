export interface Agent {
  id: number;
  machine_id?: string;
  hostname: string;
  os: string;
  ip_address: string;
  status: 'online' | 'offline';
  last_seen: string;
  created_at?: string;
  created_At?: string;
  risk_score?: number;
  version?: string;
  uptime_seconds?: number;
  mem_alloc_mb?: number;
  goroutines?: number;
}

export interface AgentSummary {
  agent_id: number;
  hostname: string;
  status: string;
  processes: number;
  connections: number;
  services: number;
  packages: number;
  users: number;
  risk_score?: number;
}

export interface Alert {
  id: number;
  agent_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  rule_name: string;
  log_message: string;
  fingerprint?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_name?: string;
  ai_summary?: string;
  ai_action?: string;
  created_at: string;
}

export interface Incident {
  id: number;
  agent_id: number;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'resolved' | 'closed';
  description: string;
  created_at: string;
  fingerprint: string;
}

// Sigma uses 'title' not 'name', and 'keywords' array
// ADD these to types/index.ts (or merge with existing SigmaRule)

export interface SigmaRule {
  id: number;
  title: string;
  description: string;
  status: string;
  severity: string;
  mitre_tactic: string;
  mitre_technique: string;
  mitre_name: string;
  logsource_cat: string;
  logsource_prod: string;
  logsource_svc: string;
  tags: string[];
  falsepositives: string[];
  references: string[];
  keywords: string[];
  selections: Record<string, string[]>;
  condition: string;
  enabled: boolean;
  hit_count?: number;
  last_matched_at?: string;
  created_at: string;
}

export interface SigmaRuleStat {
  rule_id: number;
  title: string;
  hit_count: number;
  last_matched_at: string | null;
}

export interface AnomalyFinding {
  id: number;
  agent_id: number;
  finding_type: string;
  description: string;
  severity: string;
  score: number;
  acknowledged: boolean;
  source: string;
  raw_context: Record<string, unknown>;
  created_at: string;
}

export interface AgentAnomalyScore {
  id: number;
  agent_id: number;
  tenant_id: number;
  score: number;
  components: {
    log_rate: number;
    login_anomaly: number;
    off_hours: number;
    conn_rate: number;
    detail: string;
  };
  scored_at: string;
}

export interface FleetAnomalySummary {
  agent_id: number;
  hostname: string;
  peak_score: number;
  avg_score: number;
  readings: number;
  last_scored: string;
}

export interface AgentBaseline {
  agent_id: number;
  hour_of_week: number;
  avg_log_count: number;
  avg_login_fail: number;
  avg_conn_count: number;
  sample_count: number;
  updated_at: string;
}

export interface YaraRule {
  id: number;
  name: string;
  description: string;
  rule_content: string;
  enabled: boolean;
  created_at: string;
}

export interface YaraMatch {
  id: number;
  agent_id: number;
  file_path: string;
  rule_name: string;
  severity: string;
  description: string;
  matched_strings: string;
  file_hash: string;
  created_at: string;
}
export interface IOC {
  id: number;
  indicator: string;
  type: string;
  severity: string;
  description: string;
  enabled: boolean;
  created_at: string;
}

// Firewall has source_ip, destination_ip, port
export interface FirewallRule {
  id: number;
  name: string;
  description: string;
  group_name: string;
  source_ip: string;
  destination_ip: string;
  protocol: string;
  port: number;
  action: string;
  enabled: boolean;
  priority: number;
  hit_count: number;
  synced_at: string | null;
}

export interface FirewallGroup {
  name: string;
  total_rules: number;
  enabled_rules: number;
  total_hits: number;
}

export interface FirewallConflict {
  type: 'duplicate' | 'shadow' | 'contradiction';
  severity: 'warning' | 'error';
  description: string;
  rule_a: number;
  rule_b: number;
  rule_a_name: string;
  rule_b_name: string;
}

export interface FirewallStats {
  top_rules: Array<{ id: number; name: string; group_name: string; action: string; hit_count: number }>;
  total_hits_24h: number;
  per_agent: Array<{ agent_id: number; hostname: string; hits: number }>;
}

export interface Playbook {
  id: number;
  name: string;
  trigger_type: string;
  action_type: string;
  enabled: boolean;
  created_at: string;
}

export interface PlaybookAction {
  id: number;
  playbook_id: number;
  step_order: number;
  action_type: string;
  payload: string;
  condition_expr: string;
  max_retries: number;
  retry_delay_secs: number;
  run_parallel: boolean;
  timeout_seconds: number;
  created_at: string;
}

export interface PlaybookExecution {
  id: number;
  playbook_id: number;
  agent_id: number;
  alert_rule: string;
  action_type: string;
  status: string;
  overall_status: string;
  steps_total: number;
  steps_ok: number;
  steps_failed: number;
  steps_skipped: number;
  duration_ms: number;
  created_at: string;
}

export interface PlaybookStepResult {
  id: number;
  execution_id: number;
  step_order: number;
  action_type: string;
  condition_expr: string;
  status: string;
  output: string;
  error_detail: string;
  retries_used: number;
  started_at: string;
  finished_at: string | null;
}

export interface Vulnerability {
  id: number;
  agent_id: number;
  package_name: string;
  package_version: string;
  cve_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score: number;
  name: string;
  description: string;
  remediation: string;
  detected_at: string;
  discovered_at: string;
  epss_score: number;
  epss_percentile: number;
  is_kev: boolean;
  kev_date_added?: string;
  kev_ransomware: boolean;
}

export interface AttackPathNode {
  id: string;
  type: 'internet' | 'agent';
  agent_id?: number;
  hostname?: string;
  risk_score: number;
  risk_level: string;
  max_epss: number;
  has_kev: boolean;
  kev_count: number;
  exposed: boolean;
  compromise_cost: number;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  kind: 'internet_exposure' | 'lateral';
}

export interface RankedAttackPath {
  hops: string[];
  total_cost: number;
  target_hostname: string;
  target_risk_level: string;
  score: number;
}

export interface CorrelationMatch {
  id: number;
  rule_id: number;
  rule_name: string;
  agent_id: number;
  hostname: string;
  trigger_alert_id?: number;
  incident_id?: number;
  confidence: number;
  detail: string;
  matched_at: string;
}

export interface AttackPathGraph {
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  top_paths: RankedAttackPath[];
  has_entry_point: boolean;
}

export interface NetworkMapNode {
  id: string;
  type: 'agent' | 'external_ip';
  agent_id?: number;
  hostname?: string;
  ip?: string;
  zone: 'internal' | 'dmz' | 'external';
  country?: string;
  risk_score: number;
  risk_level: string;
}

export interface NetworkMapEdge {
  source: string;
  target: string;
  protocol: string;
  port: string;
  process: string;
  count: number;
  last_seen: string;
}

export interface NetworkMapGraph {
  nodes: NetworkMapNode[];
  edges: NetworkMapEdge[];
  generated_at: string;
}

export interface TimelineEvent {
  id?: number;
  event_type: string;
  message: string;
  severity?: 'critical' | 'high' | 'medium' | 'low' | string;
  created_at: string;
}

export interface DashboardOverview {
  agents: number;
  online_agents: number;
  offline_agents: number;
  processes: number;
  connections: number;
  services: number;
  packages: number;
  users: number;
  alerts: number;
  critical_alerts: number;
  incidents: number;
  critical_incidents: number;
}

export interface ThreatFeed {
  id?: number;
  name: string;
  source: string;
  enabled: boolean;
  last_sync?: string | null;
  created_at?: string;
}

export interface Notification {
  id: string;
  type: 'alert' | 'incident' | 'task' | 'system';
  title: string;
  message: string;
  severity?: string;
  read: boolean;
  created_at: string;
}

export interface LogEntry {
  id: number;
  agent_id: number;
  log_source: string;
  log_message: string;
  parsed_fields: string; // JSON string
  collected_at: string;
}

export interface LogSearchResult {
  logs: LogEntry[];
  total: number;
  page: number;
  has_more: boolean;
}

export interface SavedLogSearch {
  id: number;
  name: string;
  query: string;
  filters: Record<string, string>;
  time_range: string;
  created_by: string;
  run_count: number;
  last_run_at: string | null;
  created_at: string;
}

export interface LogStats {
  total_logs: number;
  by_agent: Array<{ hostname: string; agent_id: number; count: number }>;
  by_source: Array<{ source: string; count: number }>;
  hourly_volume: Array<{ hour: string; count: number }>;
  retention_days: number;
}

export interface AgentRelease {
  id: number;
  platform: string;
  version: string;
  sha256: string;
  download_url: string;
  created_by: string;
  created_at: string;
}

export interface TenantDomain {
  id: number;
  tenant_id: number;
  domain: string;
  created_at: string;
}

export interface UserProfile {
  id: number;
  username: string;
  email: string;
  role: string;
  is_active: boolean;
  is_platform_admin: boolean;
  totp_enabled: boolean;
  tenant_id: number;
  tenant_name: string;
  tenant_slug: string;
  last_login: string | null;
  created_at: string | null;
}
