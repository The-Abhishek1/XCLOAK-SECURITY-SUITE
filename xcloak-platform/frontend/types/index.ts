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
  // Linux desktop metrics
  load_avg_1m?: number;
  load_avg_5m?: number;
  load_avg_15m?: number;
  logged_in_users?: number;
  open_fds?: number;
  // Mobile (Android) posture metrics
  battery_level?: number;
  battery_charging?: boolean;
  network_type?: string;
  is_rooted?: boolean;
  developer_mode?: boolean;
  storage_free_gb?: number;
  storage_total_gb?: number;
  vpn_active?: boolean;
  security_patch?: string;
  // Server-computed; populated in list endpoint
  open_alert_count?: number;
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
  hostname?: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  rule_name: string;
  log_message: string;
  fingerprint?: string;
  mitre_tactic?: string;
  mitre_technique?: string;
  mitre_name?: string;
  ai_summary?: string;
  ai_action?: string;
  status?: 'open' | 'acknowledged' | 'resolved';
  acknowledged_by?: string;
  note?: string;
  suppressed_until?: string | null;
  created_at: string;
}

export interface Incident {
  id: number;
  agent_id: number;
  hostname?: string;
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
  hit_count: number;
  last_seen: string | null;
  expires_at: string | null;
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
  port_range: string;
  direction: 'in' | 'out' | 'both';
  log_enabled: boolean;
  log_prefix: string;
  action: string;
  enabled: boolean;
  priority: number;
  tags: string[];
  expires_at: string | null;
  created_by: string;
  updated_by: string;
  updated_at: string;
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
  tag_distribution: Array<{ tag: string; count: number }>;
  expiring_soon: number;
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
  open_alert_count: number;
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
  status?: 'online' | 'offline';
  alert_count: number;
  is_ioc: boolean;
  ioc_severity?: string;
}

export interface NetworkMapEdge {
  source: string;
  target: string;
  protocol: string;
  port: string;
  service?: string;
  port_sensitivity?: 'safe' | 'neutral' | 'sensitive' | 'critical';
  port_note?: string;
  process: string;
  count: number;
  last_seen: string;
  edge_type: 'internal' | 'external';
}

export interface IPEnrichment {
  ip: string;
  is_private: boolean;
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  org?: string;
  asn?: string;
  is_proxy: boolean;
  is_hosting: boolean;
  is_ioc: boolean;
  ioc_severity?: string;
  ioc_description?: string;
  abuse_score?: number;
  abuse_reports?: number;
  abuse_categories?: string[];
  vt_malicious?: number;
  vt_suspicious?: number;
  vt_total?: number;
  threat_level: 'none' | 'low' | 'medium' | 'high' | 'critical';
  threat_tags: string[];
  sources: string[];
}

export interface NetworkMapSummary {
  total_agents: number;
  online_agents: number;
  external_ips: number;
  total_edges: number;
  ioc_hits: number;
  alerting_nodes: number;
}

export interface NetworkMapGraph {
  nodes: NetworkMapNode[];
  edges: NetworkMapEdge[];
  summary: NetworkMapSummary;
  generated_at: string;
}

export interface TimelineEvent {
  id?: number;
  agent_id?: number;
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
  open_alerts: number;
  snoozed_alerts: number;
  incidents: number;
  critical_incidents: number;
}

export interface ThreatFeed {
  id?: number;
  name: string;
  source: string;
  enabled: boolean;
  feed_type: string;
  config: Record<string, string> | string;
  last_sync?: string | null;
  tenant_id?: number;
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

export interface Case {
  id: number;
  tenant_id: number;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  status: 'open' | 'investigating' | 'contained' | 'eradicated' | 'recovered' | 'closed';
  phase: 'identification' | 'containment' | 'eradication' | 'recovery' | 'lessons_learned' | 'closed';
  assigned_to?: number;
  assigned_to_name: string;
  sla_hours: number;
  sla_breach_at?: string;
  sla_breached: boolean;
  mitre_tactic: string;
  mitre_technique: string;
  rca: string;
  closed_at?: string;
  alert_count: number;
  comment_count: number;
  created_at: string;
  updated_at: string;
}

export interface CaseComment {
  id: number;
  case_id: number;
  user_id?: number;
  username: string;
  body: string;
  is_system: boolean;
  created_at: string;
}

export interface CaseEvidence {
  id: number;
  case_id: number;
  evidence_type: string;
  reference_id?: number;
  title: string;
  description: string;
  added_by?: number;
  added_by_name: string;
  created_at: string;
}

export interface Asset {
  id: number;
  tenant_id: number;
  agent_id?: number;
  name: string;
  hostname: string;
  ip_address: string;
  asset_type: string;
  owner: string;
  business_unit: string;
  criticality: 'critical' | 'high' | 'medium' | 'low';
  data_classification: 'public' | 'internal' | 'confidential' | 'restricted';
  environment: 'production' | 'staging' | 'development' | 'test';
  location: string;
  tags: string[];
  notes: string;
  agent_status?: string;
  risk_score?: number;
  created_at: string;
  updated_at: string;
}

export interface ScheduledReport {
  id: number;
  tenant_id: number;
  name: string;
  report_type: string;
  schedule: string;
  recipients: string[];
  enabled: boolean;
  last_sent_at?: string;
  created_by?: number;
  created_at: string;
}

export interface ExecutiveMetrics {
  mttr_hours: number;
  mttd_hours: number;
  open_cases: number;
  critical_cases: number;
  sla_compliance_rate: number;
  alert_volume: Array<{ date: string; count: number }>;
  cases_by_severity: Array<{ label: string; count: number }>;
  cases_by_phase: Array<{ label: string; count: number }>;
  top_mitre_tactics: Array<{ label: string; count: number }>;
  risk_trend: Array<{ date: string; score: number }>;
  total_assets: number;
  critical_assets: number;
  online_agents: number;
  total_alerts: number;
}

export interface VulnQueueItem {
  id: number;
  agent_id: number;
  hostname: string;
  cve_id: string;
  package_name: string;
  package_version: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss_score: number;
  epss_score: number;
  is_kev: boolean;
  kev_ransomware: boolean;
  priority_score: number;
  patch_status: 'open' | 'in_progress' | 'patched' | 'accepted_risk';
  patch_notes: string;
  patch_sla_days: number | null;
  patched_at: string | null;
  asset_criticality: string;
  name: string;
  remediation: string;
}

export interface AnalystMetrics {
  username: string;
  triaged: number;
  resolved: number;
  avg_triage_minutes: number;
  open_backlog: number;
  last_active: string | null;
}

export interface SOCMetrics {
  analysts: AnalystMetrics[];
  total_open: number;
  total_acked: number;
  total_resolved: number;
  avg_mttr_minutes: number;
  backlog_trend: Array<{ date: string; count: number }>;
  alerts_by_day: Array<{ date: string; count: number }>;
}

export interface InvestigationContext {
  ioc_hits: Array<{ indicator: string; type: string; severity: string }>;
  similar_alerts: Array<{ id: number; rule_name: string; severity: string; hostname: string; created_at: string; status: string }>;
  mitre_context: { tactic: string; technique: string; name: string };
  suggested_cases: Array<{ id: number; title: string; severity: string; status: string }>;
  correlated_rules: string[];
  threat_score: number;
}

export interface PlaybookRecommendation {
  id: number;
  alert_id: number;
  tenant_id: number;
  playbook_id: number;
  playbook_name: string;
  score: number;
  reason: string;
  executed: boolean;
  executed_by: string;
  executed_at: string | null;
  created_at: string;
}

export interface ThreatActor {
  id: number;
  name: string;
  aliases: string[];
  origin_country: string;
  motivation: string;
  sophistication: string;
  description: string;
  targeted_sectors: string[];
  mitre_techniques: string[];
  is_builtin: boolean;
  recent_alert_count: number;
  created_at: string;
}

export interface NetworkAnomaly {
  id: number;
  agent_id: number;
  hostname: string;
  anomaly_type: string;
  dst_ip: string;
  dst_port: number;
  proto: string;
  deviation_score: number;
  description: string;
  is_acknowledged: boolean;
  detected_at: string;
}

export interface UserRiskProfile {
  id: number;
  tenant_id: number;
  username: string;
  source: 'endpoint' | 'platform';
  risk_score: number;
  total_events: number;
  failed_logins: number;
  off_hours_events: number;
  unique_ips: number;
  privilege_escalations: number;
  flags: string[];
  last_seen_ip: string;
  last_event_at: string | null;
  analyzed_at: string;
}

export interface UEBAEvent {
  id: number;
  tenant_id: number;
  username: string;
  event_type: string;
  severity: string;
  description: string;
  source_ip: string;
  agent_id?: number;
  raw_log?: string;
  detected_at: string;
}

export interface UserSession {
  id: number;
  tenant_id: number;
  user_id?: number;
  username: string;
  ip_address: string;
  user_agent: string;
  created_at: string;
  last_active_at: string;
  expires_at: string;
  revoked: boolean;
}

export interface TenantSecurityPolicy {
  tenant_id: number;
  session_timeout_mins: number;
  max_concurrent_sessions: number;
  mfa_required: boolean;
  updated_at: string;
}

export interface FeedSyncLog {
  id: number;
  feed_id: number;
  tenant_id: number;
  status: 'success' | 'error';
  iocs_added: number;
  error_message: string;
  synced_at: string;
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

export interface FIMAlert {
  id: number;
  agent_id: number;
  file_path: string;
  /** modified | permission_change | deleted | created */
  change_type: string;
  old_hash: string;
  new_hash: string;
  old_mode?: string;
  new_mode?: string;
  old_uid?: number;
  new_uid?: number;
  created_at: string;
}

export interface FIMBaseline {
  id: number;
  agent_id: number;
  file_path: string;
  sha256_hash: string;
  file_size: number;
  file_mode?: string;
  file_uid?: number;
  file_gid?: number;
  mod_time?: string | null;
  created_at: string;
}

export interface Connection {
  id: number;
  agent_id: number;
  protocol: string;
  local_address: string;
  remote_address: string;
  state: string;
  collected_at: string;
  /** Process that owns this socket — populated when agent runs on Linux. */
  pid?: number | null;
  process_name?: string;
  process_path?: string;
  /** GeoIP enrichment applied at ingest. */
  country?: string;
  country_code?: string;
  is_proxy?: boolean;
}
