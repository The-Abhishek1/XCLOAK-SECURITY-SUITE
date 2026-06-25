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
  severity: string;
  mitre_tactic: string;
  mitre_technique: string;
  mitre_name: string;
  keywords: string[];
  // NEW — sigma-lite
  selections: Record<string, string[]>;
  condition: string;
  enabled: boolean;
  created_at: string;
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
  source_ip: string;
  destination_ip: string;
  protocol: string;
  port: number;
  action: string;
  enabled: boolean;
  created_at?: string;
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
  created_at: string;
}

export interface PlaybookExecution {
  id: number;
  playbook_id: number;
  agent_id: number;
  alert_rule: string;
  action_type: string;
  status: string;
  created_at: string;
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
