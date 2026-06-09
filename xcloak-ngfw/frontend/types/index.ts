export interface Agent {
  id: number;
  hostname: string;
  os: string;
  ip_address: string;
  status: 'online' | 'offline';
  last_seen: string;
  created_At: string;
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
  created_at: string;
  mitre_technique?: string;
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

export interface IOC {
  id: number;
  indicator: string;
  type: 'ip' | 'domain' | 'hash' | 'url';
  severity: 'critical' | 'high' | 'medium' | 'low';
  description: string;
  enabled: boolean;
  created_at: string;
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

export interface Vulnerability {
  id: number;
  agent_id: number;
  severity: 'critical' | 'high' | 'medium' | 'low';
  name: string;
  description: string;
  remediation: string;
  discovered_at: string;
}

export interface TimelineEvent {
  event_type: 'alert' | 'playbook' | 'incident';
  message: string;
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