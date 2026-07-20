'use client';

import { useEffect, useState, useCallback, useMemo, useRef } from 'react';
import { RootLayout } from '@/components/layout/RootLayout';
import { logSourcesAPI } from '@/lib/api';
import { timeAgo } from '@/lib/utils';
import { Activity, AlertTriangle, AppWindow, ArrowRight, BarChart2, Bell, Bot, Box, Check, CheckCircle2, CheckSquare, ChevronDown, ChevronRight, Cloud, Code2, Container, Copy, Database, DbIcon, Download, Eye, EyeOff, FileText, Flame, GitBranch, Globe2, HardDrive, Info, Layers, Loader2, Lock, Mail, MonitorCheck, Network, Package, Play, PlugZap, Plus, Radio, Router, Search, Server, Settings, Shield, Square, SwitchCamera, Terminal, TestTube2, Trash2, Workflow, XCircle, Zap } from '@/lib/icon-stubs';

// ── Types ─────────────────────────────────────────────────────────────────────

interface LogSource {
  id: number; name: string; source_type: string; ip_address?: string;
  api_key_hint?: string; format: string; device_type?: string;
  enabled: boolean; last_event?: string; event_count: number;
  created_at: string; api_key?: string;
}

interface SourceHealth {
  status: 'online' | 'offline' | 'warning';
  last_event: string | null; last_heartbeat: string | null;
  eps: number; ingestion_status: string; parsing_status: string;
  auth_status: string; enabled: boolean; event_count: number;
}

interface SourceStats {
  eps: number; daily_events: number; total_logs: number;
  storage_used_mb: string; compression_ratio: string;
  parsing_errors: number; dropped_logs: number; queue_length: number;
}

interface ParserInfo {
  parser_used: string; ecs_mapping: Record<string, string>;
  field_mapping: Record<string, string>; parsing_errors: number;
  unknown_fields: string[]; parser_version: string;
}

interface RecentLog { id: number; log_source: string; log_message: string; collected_at: string; }

interface TestResult {
  connection: string; auth: string; tls: boolean; parser: string;
  permissions: string; latency_ms: number; message: string;
}

interface MonitoringData {
  online: number; offline: number; warning: number; total: number; total_eps: number;
  sources: Array<{ id: number; name: string; device_type: string; status: string; last_event: string | null; event_count: number }>;
}

interface CatalogEntry {
  id: string; label: string; category: string; subcategory: string;
  transport: 'syslog' | 'http' | 'agent' | 'api'; format: string;
  device_type: string; Icon: any; color: string; desc: string; vendor: string;
  steps: Array<{ title: string; code?: string }>;
  collection_methods: string[];
}

type DetailTab = 'health' | 'stats' | 'parser' | 'logs' | 'config' | 'test' | 'alerts';
type MainTab   = 'sources' | 'marketplace' | 'monitoring' | 'pipeline';

// ── Catalog ───────────────────────────────────────────────────────────────────

const CATALOG: CatalogEntry[] = [
  // ── Operating Systems ──────────────────────────────────────────────────────
  { id:'windows', label:'Windows', category:'Operating Systems', subcategory:'Windows', vendor:'Microsoft',
    transport:'http', format:'winevent', device_type:'windows', Icon:MonitorCheck, color:'var(--blue)',
    collection_methods:['Windows Event Forwarding','Agent','Winlogbeat','NXLog'],
    desc:'Security, System, and Application event logs via WEF or agent.',
    steps:[
      { title:'Enable Windows Event Forwarding', code:`winrm quickconfig -q\nwecutil qc -q` },
      { title:'Or ship via PowerShell', code:`$h=@{'X-Api-Key'='<key>';'Content-Type'='application/json'}\nGet-WinEvent -LogName Security -MaxEvents 100 | ConvertTo-Json |\n  Invoke-RestMethod -Uri 'https://<host>/api/ingest' -Method Post -Headers $h` },
    ] },
  { id:'linux', label:'Linux / Unix', category:'Operating Systems', subcategory:'Linux', vendor:'Generic',
    transport:'syslog', format:'syslog', device_type:'linux', Icon:Terminal, color:'var(--green)',
    collection_methods:['Syslog UDP','Syslog TCP','Syslog TLS','Agent','Filebeat','Fluent Bit'],
    desc:'System logs via rsyslog or syslog-ng — auth, daemon, kernel, auditd.',
    steps:[
      { title:'Add XCloak forwarding rule', code:`# /etc/rsyslog.d/60-xcloak.conf\n*.* @@<host>:514      # TCP\n*.* @<host>:514       # UDP` },
      { title:'Restart rsyslog', code:`sudo systemctl restart rsyslog` },
    ] },
  { id:'macos', label:'macOS', category:'Operating Systems', subcategory:'macOS', vendor:'Apple',
    transport:'syslog', format:'syslog', device_type:'macos', Icon:MonitorCheck, color:'var(--text-2)',
    collection_methods:['Syslog UDP','Syslog TCP','Unified Log (oslog)'],
    desc:'Unified logs, security events, and endpoint activity from macOS.',
    steps:[
      { title:'Stream unified log via syslog', code:`# /etc/newsyslog.conf.d/xcloak.conf\n# Use oslog to stream and pipe to rsyslog\nlog stream --predicate 'subsystem == "com.apple.security"' | nc -u <host> 514` },
    ] },
  { id:'freebsd', label:'FreeBSD / Solaris', category:'Operating Systems', subcategory:'FreeBSD', vendor:'Generic',
    transport:'syslog', format:'syslog', device_type:'freebsd', Icon:Terminal, color:'var(--orange)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'FreeBSD and Solaris system and audit logs via syslog.',
    steps:[{ title:'Configure syslog.conf', code:`*.* @<host>:514` }] },

  // ── Network Devices ────────────────────────────────────────────────────────
  { id:'palo_alto', label:'Palo Alto NGFW', category:'Network Devices', subcategory:'Firewalls', vendor:'Palo Alto Networks',
    transport:'syslog', format:'cef', device_type:'firewall', Icon:Shield, color:'var(--red)',
    collection_methods:['Syslog UDP','Syslog TCP','Syslog TLS'],
    desc:'Traffic, threat, URL, and system logs from PAN-OS in CEF format.',
    steps:[
      { title:'Device > Server Profiles > Syslog', code:`Name: xcloak\nServer: <host>:514\nFacility: LOG_USER\nFormat: CEF` },
    ] },
  { id:'fortinet', label:'FortiGate', category:'Network Devices', subcategory:'Firewalls', vendor:'Fortinet',
    transport:'syslog', format:'cef', device_type:'firewall', Icon:Shield, color:'var(--red)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'FortiOS traffic, UTM, event, and VPN logs.',
    steps:[
      { title:'CLI configuration', code:`config log syslogd setting\n  set status enable\n  set server "<host>"\n  set port 514\n  set format cef\nend` },
    ] },
  { id:'cisco_asa', label:'Cisco ASA / FTD', category:'Network Devices', subcategory:'Firewalls', vendor:'Cisco',
    transport:'syslog', format:'auto', device_type:'firewall', Icon:Shield, color:'var(--red)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'ASA and Firepower Threat Defense connection, threat, and VPN logs.',
    steps:[
      { title:'Enable remote syslog', code:`logging host inside <host> 514\nlogging trap informational\nlogging facility 16` },
    ] },
  { id:'checkpoint', label:'Check Point', category:'Network Devices', subcategory:'Firewalls', vendor:'Check Point',
    transport:'syslog', format:'cef', device_type:'firewall', Icon:Shield, color:'var(--red)',
    collection_methods:['Syslog UDP','Syslog TCP','LEA'],
    desc:'Check Point firewall, IPS, and threat prevention logs.',
    steps:[{ title:'SmartConsole log export', code:`# Security Policies > Logs > Log Servers > Add\n# Host: <host>:514 (CEF)` }] },
  { id:'pfsense', label:'pfSense / OPNsense', category:'Network Devices', subcategory:'Firewalls', vendor:'Netgate/Deciso',
    transport:'syslog', format:'auto', device_type:'firewall', Icon:Shield, color:'var(--orange)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'Open-source firewall traffic, DHCP, and auth logs.',
    steps:[{ title:'Status > System Logs > Settings', code:`Remote log server: <host>:514` }] },
  { id:'cisco_ios_router', label:'Cisco IOS Router', category:'Network Devices', subcategory:'Routers', vendor:'Cisco',
    transport:'syslog', format:'auto', device_type:'router', Icon:Router, color:'var(--accent)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'IOS/IOS-XE routing events, BGP, OSPF, and interface logs.',
    steps:[{ title:'Configure logging', code:`logging host <host>\nlogging trap informational\nlogging buffered 10000` }] },
  { id:'juniper_router', label:'Juniper Router', category:'Network Devices', subcategory:'Routers', vendor:'Juniper',
    transport:'syslog', format:'auto', device_type:'router', Icon:Router, color:'var(--green)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'JunOS routing, OSPF, BGP, and system event logs.',
    steps:[{ title:'Configure syslog', code:`set system syslog host <host> any notice` }] },
  { id:'cisco_switch', label:'Cisco Switch', category:'Network Devices', subcategory:'Switches', vendor:'Cisco',
    transport:'syslog', format:'auto', device_type:'switch', Icon:SwitchCamera, color:'var(--accent)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'Layer 2/3 switch logs — port events, VLAN, spanning tree.',
    steps:[{ title:'Configure logging', code:`logging host <host>\nlogging trap informational\nlogging facility local7` }] },
  { id:'f5', label:'F5 BIG-IP', category:'Network Devices', subcategory:'Load Balancers', vendor:'F5 Networks',
    transport:'syslog', format:'auto', device_type:'loadbalancer', Icon:Network, color:'var(--red)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'BIG-IP LTM, ASM, and APM security and access logs.',
    steps:[{ title:'Log destination', code:`tmsh modify sys log-config destination remote-high-speed-log\n  { ip-address <host> port 514 protocol udp }` }] },
  { id:'openvpn', label:'OpenVPN', category:'Network Devices', subcategory:'VPN Appliances', vendor:'OpenVPN Inc.',
    transport:'syslog', format:'auto', device_type:'vpn', Icon:Lock, color:'var(--orange)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'OpenVPN authentication, session, and tunnel logs.',
    steps:[{ title:'Configure log forwarding', code:`# rsyslog\n:programname, isequal, "openvpn" @@<host>:514` }] },
  { id:'snort_suricata', label:'Snort / Suricata', category:'Network Devices', subcategory:'IDS', vendor:'Cisco/OISF',
    transport:'syslog', format:'json', device_type:'ids', Icon:Shield, color:'var(--yellow)',
    collection_methods:['Syslog UDP','Syslog TCP','File (EVE JSON)'],
    desc:'Network intrusion detection alerts in unified2 or EVE JSON format.',
    steps:[
      { title:'Suricata EVE JSON output', code:`outputs:\n  - eve-log:\n      enabled: yes\n      filetype: syslog\n      filename: /var/log/suricata/eve.json` },
    ] },
  { id:'zeek', label:'Zeek (Bro)', category:'Network Devices', subcategory:'IDS', vendor:'Zeek Project',
    transport:'syslog', format:'json', device_type:'ids', Icon:Radio, color:'var(--yellow)',
    collection_methods:['Syslog UDP','Syslog TCP','File'],
    desc:'Network traffic analysis logs — conn, dns, http, ssl, files, and more.',
    steps:[{ title:'Forward logs via rsyslog', code:`# /etc/rsyslog.d/zeek.conf\nmodule(load="imfile")\ninput(type="imfile" File="/opt/zeek/logs/current/*.log" Tag="zeek:")` }] },
  { id:'squid', label:'Squid Proxy', category:'Network Devices', subcategory:'Proxy Servers', vendor:'Squid Project',
    transport:'syslog', format:'auto', device_type:'proxy', Icon:Globe2, color:'var(--blue)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'HTTP proxy access and cache logs for web activity monitoring.',
    steps:[{ title:'Configure syslog output', code:`access_log syslog:LOCAL1 squid` }] },

  // ── Security Products ──────────────────────────────────────────────────────
  { id:'crowdstrike', label:'CrowdStrike Falcon', category:'Security Products', subcategory:'EDR', vendor:'CrowdStrike',
    transport:'http', format:'json', device_type:'edr', Icon:Shield, color:'var(--red)',
    collection_methods:['Falcon Data Replicator','API','Streaming API'],
    desc:'Falcon EDR detections, alerts, and process telemetry via Event Streams API.',
    steps:[
      { title:'Configure Falcon Data Replicator (FDR)', code:`# Falcon UI: Data Connectors > FDR\n# Enable S3 export, then set up Lambda/SQS forwarder\naws lambda create-function --function-name xcloak-cs-forwarder ...` },
    ] },
  { id:'sentinelone', label:'SentinelOne', category:'Security Products', subcategory:'EDR', vendor:'SentinelOne',
    transport:'http', format:'json', device_type:'edr', Icon:Shield, color:'var(--accent)',
    collection_methods:['API Webhook','Syslog'],
    desc:'Endpoint threats, behavioral events, and threat hunting telemetry.',
    steps:[
      { title:'Configure Syslog Integration', code:`# Management Console: Settings > Integrations > Syslog\nIP: <host>\nPort: 514\nProtocol: TCP\nFormat: CEF` },
    ] },
  { id:'defender', label:'Microsoft Defender', category:'Security Products', subcategory:'EDR', vendor:'Microsoft',
    transport:'http', format:'json', device_type:'edr', Icon:Shield, color:'var(--blue)',
    collection_methods:['Microsoft Sentinel connector','API','Event Hub'],
    desc:'MDE alerts, incidents, and Advanced Hunting telemetry via Graph Security API.',
    steps:[
      { title:'Graph API streaming', code:`# Register app: Entra ID > App Registrations\n# Permission: ThreatHunting.Read.All\n# Stream MDE alerts:\nGET https://graph.microsoft.com/v1.0/security/alerts_v2` },
    ] },
  { id:'nessus', label:'Tenable / Nessus', category:'Security Products', subcategory:'Vulnerability Scanners', vendor:'Tenable',
    transport:'http', format:'json', device_type:'vuln_scanner', Icon:Search, color:'var(--green)',
    collection_methods:['API','Syslog'],
    desc:'Vulnerability scan results and asset risk scores via Tenable.io API.',
    steps:[{ title:'Tenable.io API export', code:`curl -X GET 'https://cloud.tenable.com/scans' -H 'X-ApiKeys: accessKey=<key>;secretKey=<secret>'` }] },
  { id:'misp', label:'MISP', category:'Security Products', subcategory:'Threat Intelligence', vendor:'MISP Project',
    transport:'http', format:'json', device_type:'threat_intel', Icon:Database, color:'var(--yellow)',
    collection_methods:['API','ZeroMQ','Kafka'],
    desc:'Threat intelligence indicators — IOCs, TTPs, and threat actor profiles.',
    steps:[{ title:'MISP Webhooks', code:`# Admin > Server Settings > Plugin.ZeroMQ_enable = true\n# Or use MISP REST API to pull events periodically` }] },
  { id:'canary', label:'Thinkst Canary', category:'Security Products', subcategory:'Honeypots', vendor:'Thinkst',
    transport:'http', format:'json', device_type:'honeypot', Icon:AlertTriangle, color:'var(--yellow)',
    collection_methods:['Webhook','Email','Syslog'],
    desc:'Honeypot alerts — canarytoken triggers, network canaries, and file canaries.',
    steps:[{ title:'Configure webhook', code:`# Canary Console: Settings > Webhooks\nURL: https://<host>/api/ingest\nHeader: X-Api-Key: <key>` }] },

  // ── Cloud Platforms ────────────────────────────────────────────────────────
  { id:'aws', label:'AWS CloudTrail', category:'Cloud Platforms', subcategory:'AWS', vendor:'Amazon',
    transport:'http', format:'json', device_type:'aws', Icon:Flame, color:'var(--orange)',
    collection_methods:['S3 + Lambda','EventBridge','CloudWatch Logs','Kinesis Firehose'],
    desc:'AWS API activity, IAM changes, S3 access, and GuardDuty findings.',
    steps:[
      { title:'Create EventBridge rule to forward to Lambda', code:`aws events put-rule --name ForwardToXCloak \\\n  --event-pattern '{"source":["aws.cloudtrail"]}'\naws events put-targets --rule ForwardToXCloak \\\n  --targets '[{"Id":"xcloak","Arn":"<lambda-arn>"}]'` },
      { title:'Lambda forwarder (Node.js)', code:`exports.handler = async (event) => {\n  await fetch('https://<host>/api/ingest', {\n    method: 'POST',\n    headers: { 'X-Api-Key': process.env.XCLOAK_KEY },\n    body: JSON.stringify(event.Records)\n  });\n};` },
    ] },
  { id:'azure', label:'Azure Monitor', category:'Cloud Platforms', subcategory:'Azure', vendor:'Microsoft',
    transport:'http', format:'json', device_type:'azure', Icon:Cloud, color:'var(--blue)',
    collection_methods:['Event Hub + Function App','Diagnostic Settings','Azure Monitor REST API'],
    desc:'Azure Activity Log, Entra ID sign-ins, Defender alerts, and resource diagnostics.',
    steps:[
      { title:'Create Diagnostic Settings', code:`az monitor diagnostic-settings create \\\n  --name XCloak --resource <subscription-id> \\\n  --event-hub-name xcloak-hub \\\n  --logs '[{"category":"Administrative","enabled":true}]'` },
    ] },
  { id:'gcp', label:'GCP Cloud Logging', category:'Cloud Platforms', subcategory:'GCP', vendor:'Google',
    transport:'http', format:'json', device_type:'gcp', Icon:Cloud, color:'var(--green)',
    collection_methods:['Pub/Sub + Cloud Functions','Cloud Storage Export','Log Router'],
    desc:'GCP Audit logs, VPC Flow Logs, and resource logs via Pub/Sub sink.',
    steps:[
      { title:'Create Pub/Sub log sink', code:`gcloud logging sinks create xcloak-sink \\\n  pubsub.googleapis.com/projects/<proj>/topics/xcloak \\\n  --log-filter='severity >= WARNING'` },
    ] },
  { id:'oracle_cloud', label:'Oracle Cloud', category:'Cloud Platforms', subcategory:'Oracle Cloud', vendor:'Oracle',
    transport:'http', format:'json', device_type:'oracle_cloud', Icon:Cloud, color:'var(--red)',
    collection_methods:['Logging Service','Events + Functions','REST API'],
    desc:'OCI Audit, VCN Flow Logs, and security events.',
    steps:[{ title:'OCI Logging connector', code:`# OCI Console: Logging > Log Groups > Service Connector\n# Source: Logs, Target: HTTP Endpoint (<host>/api/ingest)` }] },
  { id:'digitalocean', label:'DigitalOcean', category:'Cloud Platforms', subcategory:'DigitalOcean', vendor:'DigitalOcean',
    transport:'http', format:'json', device_type:'digitalocean', Icon:Cloud, color:'var(--blue)',
    collection_methods:['Spaces + Function','API'],
    desc:'DigitalOcean audit logs and firewall events.',
    steps:[{ title:'API log export', code:`curl -X GET 'https://api.digitalocean.com/v2/audit-log' \\\n  -H 'Authorization: Bearer <token>'` }] },

  // ── SaaS ──────────────────────────────────────────────────────────────────
  { id:'o365', label:'Microsoft 365', category:'SaaS', subcategory:'Microsoft 365', vendor:'Microsoft',
    transport:'http', format:'json', device_type:'o365', Icon:Mail, color:'var(--blue)',
    collection_methods:['Graph API','Management Activity API','Azure Event Hub'],
    desc:'Unified Audit Log — Exchange, SharePoint, Teams, Entra ID, and Defender events.',
    steps:[
      { title:'Enable Unified Audit Log', code:`Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true` },
      { title:'Poll via Graph API', code:`GET https://graph.microsoft.com/v1.0/security/auditLog/queries\nAuthorization: Bearer <token>` },
    ] },
  { id:'google_workspace', label:'Google Workspace', category:'SaaS', subcategory:'Google Workspace', vendor:'Google',
    transport:'http', format:'json', device_type:'google_workspace', Icon:Mail, color:'var(--green)',
    collection_methods:['Reports API','Pub/Sub Push','Google Cloud Logging'],
    desc:'Admin, Drive, Gmail, Login, Meet, and Mobile activity logs.',
    steps:[{ title:'Reports API', code:`GET https://admin.googleapis.com/admin/reports/v1/activity/users/all/applications/admin\nAuthorization: Bearer <token>` }] },
  { id:'okta', label:'Okta', category:'SaaS', subcategory:'Okta', vendor:'Okta',
    transport:'http', format:'json', device_type:'okta', Icon:Lock, color:'var(--accent)',
    collection_methods:['Event Hooks','Log Streaming (EventBridge)','System Log API'],
    desc:'Authentication, MFA, admin actions, and policy changes from Okta System Log.',
    steps:[
      { title:'Create Event Hook', code:`# Okta Admin: Workflow > Event Hooks > Create\nName: XCloak\nURL:  https://<host>/api/ingest\nHeader: X-Api-Key: <key>` },
    ] },
  { id:'slack', label:'Slack', category:'SaaS', subcategory:'Slack', vendor:'Salesforce',
    transport:'http', format:'json', device_type:'slack', Icon:Mail, color:'var(--yellow)',
    collection_methods:['Audit Logs API','Event Subscriptions'],
    desc:'Workspace audit events — message activity, file access, admin actions.',
    steps:[{ title:'Audit Logs API', code:`GET https://api.slack.com/audit/v1/logs\nAuthorization: Bearer xoxp-<token>` }] },
  { id:'github', label:'GitHub', category:'SaaS', subcategory:'GitHub', vendor:'GitHub (Microsoft)',
    transport:'http', format:'json', device_type:'github', Icon:GitBranch, color:'var(--text-2)',
    collection_methods:['Audit Log API','Webhook','GitHub Advanced Security'],
    desc:'Organization audit events, push events, secret scanning, and code scanning alerts.',
    steps:[
      { title:'Configure organization webhook', code:`# GitHub > Organization > Settings > Webhooks\nPayload URL: https://<host>/api/ingest\nContent type: application/json\nSelect: Audit log, Push, Security` },
    ] },
  { id:'gitlab', label:'GitLab', category:'SaaS', subcategory:'GitLab', vendor:'GitLab Inc.',
    transport:'http', format:'json', device_type:'gitlab', Icon:GitBranch, color:'var(--orange)',
    collection_methods:['Audit Events API','Webhook','Streaming Audit Events'],
    desc:'GitLab audit events, pipeline events, and security findings.',
    steps:[{ title:'Streaming audit events', code:`# Admin > Settings > Audit events > New streaming destination\nDestination: https://<host>/api/ingest\nHeader: X-Api-Key: <key>` }] },
  { id:'jira', label:'Jira', category:'SaaS', subcategory:'Jira', vendor:'Atlassian',
    transport:'http', format:'json', device_type:'jira', Icon:AppWindow, color:'var(--blue)',
    collection_methods:['Audit Log API','Webhooks'],
    desc:'Project and admin audit events from Jira Cloud.',
    steps:[{ title:'Audit log API', code:`GET https://<domain>.atlassian.net/rest/api/3/auditing/record\nAuthorization: Basic <base64>` }] },
  { id:'zoom', label:'Zoom', category:'SaaS', subcategory:'Zoom', vendor:'Zoom Communications',
    transport:'http', format:'json', device_type:'zoom', Icon:Mail, color:'var(--blue)',
    collection_methods:['Webhook','Activity Reports API'],
    desc:'Meeting, webinar, and admin audit events from Zoom.',
    steps:[{ title:'Configure webhook', code:`# Zoom Marketplace: App > Event Subscriptions\nEvent notification endpoint URL: https://<host>/api/ingest` }] },

  // ── Containers ─────────────────────────────────────────────────────────────
  { id:'kubernetes', label:'Kubernetes', category:'Containers', subcategory:'Kubernetes', vendor:'CNCF',
    transport:'syslog', format:'json', device_type:'kubernetes', Icon:Container, color:'var(--blue)',
    collection_methods:['Fluent Bit DaemonSet','Fluentd','OpenTelemetry Collector','API Audit Log'],
    desc:'Audit log, kubelet events, and pod stdout/stderr via Fluent Bit.',
    steps:[
      { title:'Deploy Fluent Bit DaemonSet', code:`# fluent-bit-config.yaml\n[OUTPUT]\n  Name   http\n  Host   <host>\n  Port   443\n  URI    /api/ingest\n  Header X-Api-Key <key>\n  Format json` },
      { title:'Enable K8s API audit logging', code:`# kube-apiserver:\n--audit-log-path=/var/log/kubernetes/audit.log\n--audit-policy-file=/etc/kubernetes/audit-policy.yaml` },
    ] },
  { id:'docker', label:'Docker', category:'Containers', subcategory:'Docker', vendor:'Docker Inc.',
    transport:'syslog', format:'json', device_type:'docker', Icon:Box, color:'var(--blue)',
    collection_methods:['Syslog Log Driver','Fluentd Log Driver','Docker API'],
    desc:'Container stdout/stderr and daemon events via syslog log driver.',
    steps:[
      { title:'Configure daemon syslog driver', code:`# /etc/docker/daemon.json\n{\n  "log-driver": "syslog",\n  "log-opts": {\n    "syslog-address": "udp://<host>:514",\n    "tag": "docker/{{.Name}}"\n  }\n}` },
    ] },
  { id:'openshift', label:'OpenShift', category:'Containers', subcategory:'OpenShift', vendor:'Red Hat',
    transport:'syslog', format:'json', device_type:'openshift', Icon:Container, color:'var(--red)',
    collection_methods:['Cluster Logging Operator','Fluent Bit','API Audit Log'],
    desc:'OpenShift audit, application, and infrastructure logs.',
    steps:[{ title:'Deploy Cluster Logging', code:`oc apply -f cluster-logging-forwarder.yaml\n# Forward to XCloak syslog endpoint` }] },
  { id:'rancher', label:'Rancher', category:'Containers', subcategory:'Rancher', vendor:'SUSE',
    transport:'syslog', format:'json', device_type:'rancher', Icon:Container, color:'var(--green)',
    collection_methods:['Syslog Logging Driver','Fluent Bit','Logging App'],
    desc:'Rancher cluster and workload logs across managed Kubernetes clusters.',
    steps:[{ title:'Rancher Logging app', code:`# Rancher UI: Apps > Logging\n# Add Syslog output to <host>:514` }] },

  // ── Applications ───────────────────────────────────────────────────────────
  { id:'nginx', label:'Nginx', category:'Applications', subcategory:'Nginx', vendor:'F5 / Nginx Inc.',
    transport:'syslog', format:'auto', device_type:'webserver', Icon:AppWindow, color:'var(--green)',
    collection_methods:['Syslog UDP','Syslog TCP','Filebeat','Fluent Bit'],
    desc:'HTTP access and error logs — request rate, status codes, and error patterns.',
    steps:[{ title:'Configure access log to syslog', code:`# nginx.conf\naccess_log syslog:server=<host>:514,facility=local7,tag=nginx combined;` }] },
  { id:'apache', label:'Apache httpd', category:'Applications', subcategory:'Apache', vendor:'Apache Foundation',
    transport:'syslog', format:'auto', device_type:'webserver', Icon:AppWindow, color:'var(--red)',
    collection_methods:['Syslog','Filebeat','File'],
    desc:'Apache HTTP access and error logs for web attack detection.',
    steps:[{ title:'Configure CustomLog to syslog', code:`CustomLog "|/usr/bin/logger -t apache -p local7.info" combined\nErrorLog syslog:local7` }] },
  { id:'iis', label:'IIS', category:'Applications', subcategory:'IIS', vendor:'Microsoft',
    transport:'http', format:'json', device_type:'webserver', Icon:AppWindow, color:'var(--blue)',
    collection_methods:['NXLog','Winlogbeat','Agent'],
    desc:'IIS web server logs for Windows environments.',
    steps:[{ title:'Ship via NXLog', code:`# NXLog config:\n<Output xcloak>\n  Module om_http\n  URL https://<host>/api/ingest\n  HTTPSCertFile ... \n</Output>` }] },
  { id:'redis', label:'Redis', category:'Applications', subcategory:'Redis', vendor:'Redis Inc.',
    transport:'syslog', format:'auto', device_type:'database', Icon:DbIcon, color:'var(--red)',
    collection_methods:['Syslog','Filebeat'],
    desc:'Redis slow log, command audit, and connection events.',
    steps:[{ title:'Configure syslog in redis.conf', code:`syslog-enabled yes\nsyslog-ident redis\nsyslog-facility local0` }] },
  { id:'kafka', label:'Apache Kafka', category:'Applications', subcategory:'Kafka', vendor:'Apache Foundation',
    transport:'syslog', format:'json', device_type:'kafka', Icon:Radio, color:'var(--orange)',
    collection_methods:['Syslog','JMX Metrics','Filebeat'],
    desc:'Kafka broker logs and audit events for data pipeline security.',
    steps:[{ title:'Configure log4j to syslog', code:`# log4j.properties:\nlog4j.appender.syslog=org.apache.log4j.net.SyslogAppender\nlog4j.appender.syslog.SyslogHost=<host>` }] },
  { id:'rabbitmq', label:'RabbitMQ', category:'Applications', subcategory:'RabbitMQ', vendor:'Broadcom / VMware',
    transport:'syslog', format:'auto', device_type:'rabbitmq', Icon:Radio, color:'var(--orange)',
    collection_methods:['Syslog','Filebeat','Management API'],
    desc:'RabbitMQ broker, auth, and connection events.',
    steps:[{ title:'Configure syslog handler', code:`# rabbitmq.conf:\nlog.syslog = true\nlog.syslog.transport = tcp\nlog.syslog.host = <host>\nlog.syslog.port = 514` }] },

  // ── Databases ──────────────────────────────────────────────────────────────
  { id:'postgresql', label:'PostgreSQL', category:'Databases', subcategory:'PostgreSQL', vendor:'PostgreSQL Global Dev Group',
    transport:'syslog', format:'auto', device_type:'database', Icon:DbIcon, color:'var(--blue)',
    collection_methods:['Syslog','Filebeat','pgaudit extension'],
    desc:'Database audit, query, and connection logs with pgaudit for fine-grained logging.',
    steps:[{ title:'Configure postgresql.conf', code:`log_destination = 'syslog'\nsyslog_facility = 'LOCAL0'\nlog_connections = on\nlog_statement = 'ddl'` }] },
  { id:'mysql', label:'MySQL / MariaDB', category:'Databases', subcategory:'MySQL', vendor:'Oracle / MariaDB Corp',
    transport:'syslog', format:'auto', device_type:'database', Icon:DbIcon, color:'var(--orange)',
    collection_methods:['Syslog','Filebeat','File'],
    desc:'General, slow, and error log for SQL injection and privilege abuse detection.',
    steps:[{ title:'Enable general log', code:`[mysqld]\ngeneral_log = 1\ngeneral_log_file = /var/log/mysql/mysql.log` }] },
  { id:'mongodb', label:'MongoDB', category:'Databases', subcategory:'MongoDB', vendor:'MongoDB Inc.',
    transport:'syslog', format:'json', device_type:'database', Icon:DbIcon, color:'var(--green)',
    collection_methods:['Syslog','Filebeat','Ops Manager'],
    desc:'MongoDB audit, slow query, and connection logs in JSON format.',
    steps:[{ title:'Configure mongod.conf', code:`systemLog:\n  destination: syslog\n  path: ""\nsetParameter:\n  auditLog:\n    destination: syslog\n    format: JSON` }] },
  { id:'mssql', label:'SQL Server', category:'Databases', subcategory:'SQL Server', vendor:'Microsoft',
    transport:'http', format:'json', device_type:'database', Icon:DbIcon, color:'var(--red)',
    collection_methods:['NXLog','Winlogbeat','SQL Server Audit'],
    desc:'SQL Server audit, login, and error log events.',
    steps:[{ title:'Enable SQL Server Audit', code:`USE master;\nCREATE SERVER AUDIT XCloak TO FILE (FILEPATH='C:\\audit\\');\nCREATE SERVER AUDIT SPECIFICATION XCloakSpec FOR SERVER AUDIT XCloak ADD (FAILED_LOGIN_GROUP);` }] },
  { id:'elasticsearch', label:'Elasticsearch', category:'Databases', subcategory:'Elasticsearch', vendor:'Elastic',
    transport:'syslog', format:'json', device_type:'database', Icon:Search, color:'var(--yellow)',
    collection_methods:['Filebeat','Logstash','API'],
    desc:'Elasticsearch slow logs, audit, and security events.',
    steps:[{ title:'Enable audit logging', code:`xpack.security.audit.enabled: true\nxpack.security.audit.logfile.events.emit_request_body: false` }] },

  // ── Infrastructure ─────────────────────────────────────────────────────────
  { id:'dns', label:'DNS Server', category:'Infrastructure', subcategory:'DNS', vendor:'ISC / Microsoft',
    transport:'syslog', format:'auto', device_type:'dns', Icon:Globe2, color:'var(--blue)',
    collection_methods:['Syslog UDP','Syslog TCP','File'],
    desc:'DNS query and response logs for DGA detection and data exfiltration analysis.',
    steps:[
      { title:'BIND9 query logging', code:`# /etc/named.conf\nlogging {\n  channel syslog_chan { syslog local2; severity info; };\n  category queries { syslog_chan; };\n};` },
    ] },
  { id:'dhcp', label:'DHCP Server', category:'Infrastructure', subcategory:'DHCP', vendor:'ISC / Microsoft',
    transport:'syslog', format:'auto', device_type:'dhcp', Icon:Globe2, color:'var(--blue)',
    collection_methods:['Syslog UDP','Syslog TCP','File'],
    desc:'IP lease assignments to correlate IPs to hostnames and MACs.',
    steps:[{ title:'ISC DHCP syslog', code:`# dhcpd.conf\nlog-facility local7;\n\n# rsyslog\nlocal7.* @<host>:514` }] },
  { id:'active_directory', label:'Active Directory', category:'Infrastructure', subcategory:'Active Directory', vendor:'Microsoft',
    transport:'http', format:'winevent', device_type:'active_directory', Icon:Lock, color:'var(--blue)',
    collection_methods:['Windows Event Forwarding','Agent','LDAP Polling'],
    desc:'AD authentication, account changes, group membership, and policy events.',
    steps:[{ title:'Forward DC events via WEF', code:`# On Domain Controller:\nwinrm quickconfig -q\nwecutil qc -q\n# Create subscription targeting XCloak WEF collector` }] },
  { id:'vmware', label:'VMware ESXi', category:'Infrastructure', subcategory:'Hyper-V', vendor:'Broadcom / VMware',
    transport:'syslog', format:'auto', device_type:'vmware', Icon:Server, color:'var(--green)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'ESXi host system, auth, and VM activity logs.',
    steps:[{ title:'Configure ESXi syslog', code:`esxcli system syslog config set --loghost='udp://<host>:514'\nesxcli system syslog reload` }] },
  { id:'proxmox', label:'Proxmox VE', category:'Infrastructure', subcategory:'Proxmox', vendor:'Proxmox Server Solutions',
    transport:'syslog', format:'auto', device_type:'proxmox', Icon:Server, color:'var(--orange)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'Proxmox VE hypervisor, VM, and container lifecycle events.',
    steps:[{ title:'Configure rsyslog', code:`# /etc/rsyslog.d/60-xcloak.conf\n*.* @@<host>:514` }] },
  { id:'radius', label:'RADIUS / NPS', category:'Infrastructure', subcategory:'RADIUS', vendor:'Various',
    transport:'syslog', format:'auto', device_type:'radius', Icon:Lock, color:'var(--yellow)',
    collection_methods:['Syslog UDP','Syslog TCP'],
    desc:'RADIUS authentication success/failure for VPN and 802.1X access control.',
    steps:[{ title:'Forward via rsyslog', code:`# rsyslog: forward radius daemon logs\n:programname, isequal, "radiusd" @@<host>:514` }] },
];

const CAT_ORDER = ['Operating Systems','Network Devices','Security Products','Cloud Platforms','SaaS','Containers','Applications','Databases','Infrastructure'];

const CAT_COLOR: Record<string, string> = {
  'Operating Systems':  'var(--green)',
  'Network Devices':    'var(--accent)',
  'Security Products':  'var(--red)',
  'Cloud Platforms':    'var(--orange)',
  'SaaS':               'var(--yellow)',
  'Containers':         'var(--blue)',
  'Applications':       'var(--green)',
  'Databases':          'var(--yellow)',
  'Infrastructure':     'var(--text-2)',
};

const CAT_ICON: Record<string, any> = {
  'Operating Systems':  Terminal,
  'Network Devices':    Network,
  'Security Products':  Shield,
  'Cloud Platforms':    Cloud,
  'SaaS':               Mail,
  'Containers':         Container,
  'Applications':       AppWindow,
  'Databases':          Database,
  'Infrastructure':     Server,
};

// ── Helpers ───────────────────────────────────────────────────────────────────

function CodeBlock({ code, host }: { code: string; host: string }) {
  const [copied, setCopied] = useState(false);
  const text = code.replace(/<host>/g, host || '<host>');
  return (
    <div className="relative group rounded-lg overflow-hidden" style={{ background:'var(--bg-0)', border:'1px solid var(--border)' }}>
      <pre className="text-[10px] font-mono leading-relaxed p-3 pr-10 overflow-x-auto whitespace-pre-wrap break-all" style={{ color:'var(--text-2)' }}>{text}</pre>
      <button onClick={() => { navigator.clipboard.writeText(text); setCopied(true); setTimeout(()=>setCopied(false),2000); }}
        className="absolute top-2 right-2 p-1.5 rounded opacity-0 group-hover:opacity-100 transition-opacity"
        style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
        {copied ? <Check className="h-3 w-3" style={{ color:'var(--green)' }} /> : <Copy className="h-3 w-3" style={{ color:'var(--text-3)' }} />}
      </button>
    </div>
  );
}

function StatusBadge({ status }: { status?: string }) {
  if (status === 'online')  return <span className="flex items-center gap-1 text-[10px] font-medium" style={{ color:'var(--green)' }}><span className="h-1.5 w-1.5 rounded-full animate-pulse" style={{ background:'var(--green)' }} />Online</span>;
  if (status === 'warning') return <span className="flex items-center gap-1 text-[10px] font-medium" style={{ color:'var(--yellow)' }}><AlertTriangle className="h-3 w-3" />Warning</span>;
  return <span className="flex items-center gap-1 text-[10px] font-medium" style={{ color:'var(--text-3)' }}><XCircle className="h-3 w-3" />Offline</span>;
}

function StatusIcon({ status }: { status?: string }) {
  if (status === 'online')  return <span className="h-2 w-2 rounded-full flex-shrink-0 animate-pulse" style={{ background:'var(--green)' }} />;
  if (status === 'warning') return <span className="h-2 w-2 rounded-full flex-shrink-0" style={{ background:'var(--yellow)' }} />;
  return <span className="h-2 w-2 rounded-full flex-shrink-0" style={{ background:'var(--border)' }} />;
}

// ── Connect Modal ─────────────────────────────────────────────────────────────

function ConnectModal({ def, onClose, onCreated, host }: {
  def: CatalogEntry; onClose: () => void; onCreated: (src: LogSource) => void; host: string;
}) {
  const [form, setForm] = useState({ name: def.label, source_type: def.transport === 'syslog' ? 'syslog' : 'http', format: def.format, device_type: def.id, ip_address: '' });
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState('');
  const [openStep, setOpenStep] = useState(0);
  const [showKey, setShowKey]   = useState(false);
  const [newKey, setNewKey]     = useState('');
  const [copied, setCopied]     = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault(); setSaving(true); setError('');
    try {
      const r = await logSourcesAPI.create(form);
      const src: LogSource = r.data;
      if (src.api_key) setNewKey(src.api_key); else { onCreated(src); onClose(); }
    } catch (err: any) { setError(err?.response?.data?.error || 'Failed to create source'); }
    finally { setSaving(false); }
  };

  if (newKey) return (
    <div className="g-modal-backdrop" onClick={onClose}>
      <div className="g-modal" style={{ maxWidth:460 }} onClick={e=>e.stopPropagation()}>
        <div className="p-6 space-y-4">
          <div className="flex items-center gap-2"><CheckCircle2 className="h-5 w-5" style={{ color:'var(--green)' }} /><p className="font-semibold text-sm" style={{ color:'var(--text-1)' }}>Source created — save your API key</p></div>
          <p className="text-xs" style={{ color:'var(--text-3)' }}>This key is shown <strong>once</strong> and cannot be recovered.</p>
          <div className="flex items-center gap-2 rounded-lg px-3 py-2" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
            <code className="flex-1 text-xs font-mono break-all" style={{ color:'var(--text-1)' }}>{showKey ? newKey : '•'.repeat(40)}</code>
            <button onClick={()=>setShowKey(v=>!v)} style={{ color:'var(--text-3)' }}>{showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}</button>
            <button onClick={()=>{ navigator.clipboard.writeText(newKey); setCopied(true); setTimeout(()=>setCopied(false),2000); }}>
              {copied ? <Check className="h-4 w-4" style={{ color:'var(--green)' }} /> : <Copy className="h-4 w-4" style={{ color:'var(--text-3)' }} />}
            </button>
          </div>
          <CodeBlock code={`POST https://<host>/api/ingest\nX-Api-Key: ${newKey}\nContent-Type: application/json\n\n[{ "log": "your log line here" }]`} host={host} />
          <button onClick={onClose} className="g-btn g-btn-primary w-full justify-center">I've saved the key</button>
        </div>
      </div>
    </div>
  );

  return (
    <div className="g-modal-backdrop" onClick={onClose}>
      <div className="g-modal" style={{ maxWidth:780, maxHeight:'90vh', display:'flex', flexDirection:'column' }} onClick={e=>e.stopPropagation()}>
        <div className="flex items-center gap-3 px-6 py-4 shrink-0" style={{ borderBottom:'1px solid var(--border)' }}>
          <div className="h-9 w-9 rounded-xl flex items-center justify-center shrink-0" style={{ background:`${def.color}22`, border:`1px solid ${def.color}44` }}>
            <def.Icon className="h-5 w-5" style={{ color:def.color }} />
          </div>
          <div>
            <p className="text-sm font-semibold" style={{ color:'var(--text-1)' }}>Connect {def.label}</p>
            <p className="text-xs" style={{ color:'var(--text-3)' }}>{def.desc}</p>
          </div>
          <button onClick={onClose} className="ml-auto p-1.5 rounded-lg hover:bg-[var(--glass-hover)]" style={{ color:'var(--text-3)', fontSize: 18, lineHeight: 1 }} title="Close">×</button>
        </div>
        <div className="flex flex-1 min-h-0 overflow-hidden">
          <div className="w-[55%] border-r overflow-y-auto p-5 space-y-2" style={{ borderColor:'var(--border)' }}>
            <p className="text-[10px] font-bold uppercase tracking-wider mb-3" style={{ color:'var(--text-3)' }}>Setup Instructions</p>
            <div className="flex flex-wrap gap-1 mb-3">
              {def.collection_methods.map(m => (
                <span key={m} className="text-[9px] px-2 py-0.5 rounded-full font-medium" style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>{m}</span>
              ))}
            </div>
            {def.steps.map((step, i) => (
              <div key={i} className="rounded-xl overflow-hidden" style={{ border:'1px solid var(--border)' }}>
                <button className="w-full flex items-center gap-2 px-3 py-2.5 text-left hover:bg-[var(--glass-hover)] transition-colors"
                  onClick={()=>setOpenStep(openStep===i ? -1 : i)}>
                  <span className="h-4 w-4 rounded-full text-[10px] font-bold flex items-center justify-center shrink-0"
                    style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>{i+1}</span>
                  <span className="text-xs font-medium" style={{ color:'var(--text-1)' }}>{step.title}</span>
                  <span className="ml-auto">{openStep===i ? <ChevronDown className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} /> : <ChevronRight className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}</span>
                </button>
                {openStep===i && step.code && <div className="px-3 pb-3"><CodeBlock code={step.code} host={host} /></div>}
              </div>
            ))}
          </div>
          <div className="flex-1 overflow-y-auto p-5">
            <p className="text-[10px] font-bold uppercase tracking-wider mb-3" style={{ color:'var(--text-3)' }}>Source Configuration</p>
            <form id="connect-form" onSubmit={submit} className="space-y-3">
              <div><label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Display Name</label>
                <input required value={form.name} onChange={e=>setForm(f=>({...f,name:e.target.value}))} className="g-input w-full text-xs" /></div>
              <div><label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Transport</label>
                <select value={form.source_type} onChange={e=>setForm(f=>({...f,source_type:e.target.value}))} className="g-select w-full text-xs">
                  <option value="syslog">Syslog (UDP/TCP/TLS)</option>
                  <option value="http">HTTP Webhook / REST</option>
                </select></div>
              {form.source_type === 'syslog' && (
                <div><label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Source IP (blank = accept any)</label>
                  <input value={form.ip_address} onChange={e=>setForm(f=>({...f,ip_address:e.target.value}))}
                    placeholder="10.0.0.1" className="g-input w-full text-xs font-mono" /></div>
              )}
              <div><label className="text-[10px] mb-1 block" style={{ color:'var(--text-3)' }}>Log Format</label>
                <select value={form.format} onChange={e=>setForm(f=>({...f,format:e.target.value}))} className="g-select w-full text-xs">
                  {['auto','syslog','cef','leef','json','ndjson','winevent','text'].map(v=><option key={v} value={v}>{v}</option>)}
                </select></div>
              {form.source_type === 'syslog' && (
                <div className="rounded-xl p-3 space-y-1" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                  <p className="text-[10px] font-semibold mb-1" style={{ color:'var(--text-2)' }}>XCloak Syslog Receiver</p>
                  <CodeBlock code={`<host>:514   UDP\n<host>:514   TCP\n<host>:6514  TLS`} host={host} />
                </div>
              )}
              {form.source_type === 'http' && (
                <div className="rounded-xl p-3 space-y-1" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                  <p className="text-[10px] font-semibold mb-1" style={{ color:'var(--text-2)' }}>Ingest Endpoint</p>
                  <CodeBlock code={`POST https://<host>/api/ingest\nX-Api-Key: <key-shown-after-save>\nContent-Type: application/json`} host={host} />
                </div>
              )}
              {error && <p className="text-xs" style={{ color:'var(--red)' }}>{error}</p>}
            </form>
          </div>
        </div>
        <div className="flex gap-3 px-6 py-4 shrink-0" style={{ borderTop:'1px solid var(--border)' }}>
          <button onClick={onClose} className="g-btn g-btn-ghost flex-1 justify-center">Cancel</button>
          <button type="submit" form="connect-form" disabled={saving} className="g-btn g-btn-primary flex-1 justify-center">
            {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Connect Source'}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── Detail Panel ──────────────────────────────────────────────────────────────

function SourceDetailPanel({ src, def, onClose, onToggle, onDelete, host }: {
  src: LogSource; def: CatalogEntry | undefined; onClose: () => void;
  onToggle: () => void; onDelete: () => void; host: string;
}) {
  const [tab, setTab]         = useState<DetailTab>('health');
  const [health, setHealth]   = useState<SourceHealth | null>(null);
  const [stats, setStats]     = useState<SourceStats | null>(null);
  const [parser, setParser]   = useState<ParserInfo | null>(null);
  const [logs, setLogs]       = useState<RecentLog[]>([]);
  const [testResult, setTest] = useState<TestResult | null>(null);
  const [testing, setTesting] = useState(false);
  const [loadingLogs, setLoadingLogs] = useState(false);

  useEffect(() => {
    logSourcesAPI.getHealth(src.id).then(r => r.data && setHealth(r.data));
  }, [src.id]);

  useEffect(() => {
    if (tab === 'stats' && !stats)   logSourcesAPI.getStats(src.id).then(r => r.data && setStats(r.data));
    if (tab === 'parser' && !parser) logSourcesAPI.getParser(src.id).then(r => r.data && setParser(r.data));
    if (tab === 'logs' && logs.length === 0) {
      setLoadingLogs(true);
      logSourcesAPI.getRecentLogs(src.id).then(r => { setLogs(r.data?.logs ?? []); setLoadingLogs(false); });
    }
  }, [tab, src.id]);

  const runTest = async () => {
    setTesting(true); setTest(null);
    try { const r = await logSourcesAPI.test(src.id); setTest(r.data as TestResult); }
    catch { setTest({ connection:'error', auth:'unknown', tls:false, parser:'unknown', permissions:'unknown', latency_ms:0, message:'Test request failed.' }); }
    finally { setTesting(false); }
  };

  const TABS: Array<{id: DetailTab; label: string; Icon: any}> = [
    { id:'health', label:'Health',   Icon:Activity },
    { id:'stats',  label:'Stats',    Icon:BarChart2 },
    { id:'parser', label:'Parser',   Icon:Code2 },
    { id:'logs',   label:'Logs',     Icon:FileText },
    { id:'config', label:'Config',   Icon:Settings },
    { id:'test',   label:'Test',     Icon:TestTube2 },
    { id:'alerts', label:'Alerts',   Icon:Bell },
  ];

  const StatusChip = ({ val }: { val: string }) => {
    const ok = val === 'ok' || val === 'running' || val === 'online';
    const warn = val === 'warning' || val === 'no_events';
    return (
      <span className="text-[10px] px-2 py-0.5 rounded font-mono"
        style={{ background: ok ? 'rgba(var(--green-rgb,34,197,94),0.1)' : warn ? 'rgba(234,179,8,0.1)' : 'rgba(248,81,73,0.1)',
                 color: ok ? 'var(--green)' : warn ? 'var(--yellow)' : 'var(--red)',
                 border: `1px solid ${ok ? 'var(--green)' : warn ? 'var(--yellow)' : 'var(--red)'}44` }}>
        {val}
      </span>
    );
  };

  return (
    <div className="flex flex-col h-full" style={{ borderLeft:'1px solid var(--border)' }}>
      {/* Header */}
      <div className="flex items-center gap-3 px-4 py-3 shrink-0" style={{ borderBottom:'1px solid var(--border)' }}>
        {def && (
          <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0" style={{ background:`${def.color}22`, border:`1px solid ${def.color}44` }}>
            <def.Icon className="h-4 w-4" style={{ color:def.color }} />
          </div>
        )}
        <div className="flex-1 min-w-0">
          <p className="text-xs font-semibold truncate" style={{ color:'var(--text-1)' }}>{src.name}</p>
          <p className="text-[10px]" style={{ color:'var(--text-3)' }}>{def?.label ?? src.device_type} · {src.source_type}</p>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          <button onClick={onToggle} className="g-btn g-btn-ghost text-[10px] py-1 px-2" title={src.enabled ? 'Disable' : 'Enable'}>
            {src.enabled ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
          </button>
          <button onClick={onDelete} className="g-btn g-btn-ghost text-[10px] py-1 px-2" style={{ color:'var(--red)' }} title="Delete">🗑️</button>
          <button onClick={onClose} className="g-btn g-btn-ghost text-[10px] py-1 px-2" title="Close">×</button>
        </div>
      </div>

      {/* Tab strip */}
      <div className="flex overflow-x-auto shrink-0" style={{ borderBottom:'1px solid var(--border)', scrollbarWidth:'none' }}>
        {TABS.map(t => (
          <button key={t.id} onClick={() => setTab(t.id)}
            className="flex items-center gap-1 px-3 py-2 text-[10px] font-medium whitespace-nowrap shrink-0 border-b-2 transition-colors"
            style={{ borderColor: tab===t.id ? 'var(--accent)' : 'transparent', color: tab===t.id ? 'var(--accent)' : 'var(--text-3)' }}>
            <t.Icon className="h-3 w-3" />{t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-3 text-xs">

        {/* ── Health ── */}
        {tab === 'health' && (
          <>
            <div className="flex items-center gap-3">
              <StatusBadge status={health?.status ?? (src.enabled ? 'warning' : 'offline')} />
              {health && <span className="text-[10px]" style={{ color:'var(--text-3)' }}>EPS: <span style={{ color:'var(--accent)' }}>{health.eps}</span></span>}
            </div>
            {[
              { label:'Last Event',       val: src.last_event ? timeAgo(src.last_event) : 'Never' },
              { label:'Last Heartbeat',   val: health?.last_heartbeat ? timeAgo(health.last_heartbeat) : 'Never' },
              { label:'Total Events',     val: src.event_count.toLocaleString() },
              { label:'Source Type',      val: src.source_type },
              { label:'Format',           val: src.format },
            ].map(({ label, val }) => (
              <div key={label} className="flex items-center justify-between py-1.5" style={{ borderBottom:'1px solid var(--border)' }}>
                <span style={{ color:'var(--text-3)' }}>{label}</span>
                <span className="font-mono" style={{ color:'var(--text-1)' }}>{val}</span>
              </div>
            ))}
            {health && (
              <div className="space-y-2 pt-2">
                <p className="text-[10px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>Status Checks</p>
                {[
                  { label:'Ingestion',  val: health.ingestion_status },
                  { label:'Parsing',    val: health.parsing_status },
                  { label:'Auth',       val: health.auth_status },
                ].map(({ label, val }) => (
                  <div key={label} className="flex items-center justify-between">
                    <span style={{ color:'var(--text-2)' }}>{label}</span>
                    <StatusChip val={val} />
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* ── Stats ── */}
        {tab === 'stats' && (
          <>
            {!stats ? <div className="flex justify-center py-8"><Loader2 className="h-4 w-4 animate-spin" style={{ color:'var(--text-3)' }} /></div> : (
              <div className="space-y-2">
                {[
                  { label:'Events / Second',   val: stats.eps.toString(),           color:'var(--accent)' },
                  { label:'Daily Events',      val: stats.daily_events.toLocaleString() },
                  { label:'Total Logs',        val: stats.total_logs.toLocaleString() },
                  { label:'Storage Used',      val: `${stats.storage_used_mb} MB` },
                  { label:'Compression',       val: stats.compression_ratio },
                  { label:'Parsing Errors',    val: stats.parsing_errors.toString(), color: stats.parsing_errors > 0 ? 'var(--red)' : undefined },
                  { label:'Dropped Logs',      val: stats.dropped_logs.toString(),   color: stats.dropped_logs > 0 ? 'var(--red)' : undefined },
                  { label:'Queue Length',      val: stats.queue_length.toString() },
                ].map(({ label, val, color }) => (
                  <div key={label} className="flex items-center justify-between py-1.5" style={{ borderBottom:'1px solid var(--border)' }}>
                    <span style={{ color:'var(--text-3)' }}>{label}</span>
                    <span className="font-mono font-semibold tabular-nums" style={{ color: color ?? 'var(--text-1)' }}>{val}</span>
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* ── Parser ── */}
        {tab === 'parser' && (
          <>
            {!parser ? <div className="flex justify-center py-8"><Loader2 className="h-4 w-4 animate-spin" style={{ color:'var(--text-3)' }} /></div> : (
              <>
                <div className="flex items-center justify-between"><span style={{ color:'var(--text-3)' }}>Parser</span><span className="font-mono text-[11px]" style={{ color:'var(--accent)' }}>{parser.parser_used}</span></div>
                <div className="flex items-center justify-between"><span style={{ color:'var(--text-3)' }}>Version</span><span className="font-mono text-[11px]" style={{ color:'var(--text-2)' }}>{parser.parser_version}</span></div>
                <p className="text-[10px] font-bold uppercase tracking-wider pt-2" style={{ color:'var(--text-3)' }}>ECS Field Mapping</p>
                <div className="rounded-xl overflow-hidden" style={{ border:'1px solid var(--border)' }}>
                  {Object.entries(parser.ecs_mapping).map(([from, to], i) => (
                    <div key={from} className="flex items-center gap-2 px-3 py-1.5 text-[10px]"
                      style={{ background: i%2===0 ? 'transparent' : 'rgba(255,255,255,0.01)', borderBottom: '1px solid var(--border)' }}>
                      <span className="font-mono w-24 shrink-0" style={{ color:'var(--text-3)' }}>{from}</span>
                      <ArrowRight className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} />
                      <span className="font-mono" style={{ color:'var(--accent)' }}>{to}</span>
                    </div>
                  ))}
                </div>
                <p className="text-[10px] font-bold uppercase tracking-wider pt-1" style={{ color:'var(--text-3)' }}>Field Mapping</p>
                <div className="rounded-xl overflow-hidden" style={{ border:'1px solid var(--border)' }}>
                  {Object.entries(parser.field_mapping).map(([from, to], i) => (
                    <div key={from} className="flex items-center gap-2 px-3 py-1.5 text-[10px]"
                      style={{ background: i%2===0 ? 'transparent' : 'rgba(255,255,255,0.01)', borderBottom: '1px solid var(--border)' }}>
                      <span className="font-mono w-24 shrink-0" style={{ color:'var(--text-3)' }}>{from}</span>
                      <ArrowRight className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} />
                      <span className="font-mono" style={{ color:'var(--green)' }}>{to}</span>
                    </div>
                  ))}
                </div>
                {/* Normalization flow */}
                <p className="text-[10px] font-bold uppercase tracking-wider pt-1" style={{ color:'var(--text-3)' }}>Normalization Pipeline</p>
                {['Original','Normalized','Enriched','Indexed'].map((stage, i, arr) => (
                  <div key={stage} className="flex flex-col items-center">
                    <div className="w-full rounded-lg px-3 py-2 text-[11px] font-medium text-center"
                      style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-2)' }}>
                      {stage}
                    </div>
                    {i < arr.length - 1 && <div className="h-4 w-px" style={{ background:'var(--border)' }} />}
                  </div>
                ))}
              </>
            )}
          </>
        )}

        {/* ── Recent Logs ── */}
        {tab === 'logs' && (
          <>
            {loadingLogs ? <div className="flex justify-center py-8"><Loader2 className="h-4 w-4 animate-spin" style={{ color:'var(--text-3)' }} /></div>
            : logs.length === 0 ? <p className="text-center py-8" style={{ color:'var(--text-3)' }}>No recent logs found</p>
            : logs.map((l, i) => (
              <div key={l.id} className="rounded-lg p-2.5 space-y-1" style={{ background:'var(--bg-0)', border:'1px solid var(--border)' }}>
                <div className="flex items-center justify-between">
                  <span className="text-[9px] font-mono" style={{ color:'var(--text-3)' }}>{new Date(l.collected_at).toLocaleTimeString()}</span>
                  <span className="text-[9px]" style={{ color:'var(--text-3)' }}>#{i+1}</span>
                </div>
                <p className="text-[10px] font-mono leading-relaxed break-all" style={{ color:'var(--text-1)' }}>{l.log_message.slice(0, 200)}</p>
              </div>
            ))}
          </>
        )}

        {/* ── Config ── */}
        {tab === 'config' && (
          <div className="space-y-2">
            {[
              { label:'Source ID',        val: src.id.toString() },
              { label:'Name',             val: src.name },
              { label:'Transport',        val: src.source_type },
              { label:'Format',           val: src.format },
              { label:'Device Type',      val: src.device_type || '—' },
              { label:'Address / Key',    val: src.source_type === 'syslog' ? (src.ip_address || 'Any') : (src.api_key_hint ? `…${src.api_key_hint}` : '—') },
              { label:'Created',          val: new Date(src.created_at).toLocaleDateString() },
              { label:'TLS',              val: src.source_type === 'http' ? 'Yes (HTTPS)' : 'Port 6514 optional' },
              { label:'Timezone',         val: 'UTC (server default)' },
              { label:'Rate Limit',       val: '10 MB / 5,000 events per request' },
              { label:'Retention',        val: '90 days (tenant default)' },
            ].map(({ label, val }) => (
              <div key={label} className="flex items-start justify-between py-1.5" style={{ borderBottom:'1px solid var(--border)' }}>
                <span style={{ color:'var(--text-3)' }}>{label}</span>
                <span className="font-mono text-right" style={{ color:'var(--text-1)', maxWidth:'55%', wordBreak:'break-all' }}>{val}</span>
              </div>
            ))}
          </div>
        )}

        {/* ── Test ── */}
        {tab === 'test' && (
          <>
            <p style={{ color:'var(--text-3)' }}>Run a connectivity and authentication test for this source.</p>
            <button onClick={runTest} disabled={testing} className="g-btn g-btn-primary w-full justify-center">
              {testing ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Running test…</> : <><Play className="h-3.5 w-3.5" /> Run Test</>}
            </button>
            {testResult && (
              <div className="space-y-2 pt-2">
                <div className={`rounded-xl px-4 py-3 text-xs font-medium ${testResult.connection==='ok'?'':'border'}`}
                  style={{ background: testResult.connection==='ok' ? 'rgba(34,197,94,0.08)' : 'rgba(248,81,73,0.08)', color: testResult.connection==='ok' ? 'var(--green)' : 'var(--red)', border:`1px solid ${testResult.connection==='ok'?'rgba(34,197,94,0.3)':'rgba(248,81,73,0.3)'}` }}>
                  {testResult.message}
                </div>
                {[
                  { label:'Connection',  val: testResult.connection },
                  { label:'Auth',        val: testResult.auth },
                  { label:'TLS',         val: testResult.tls ? 'enabled' : 'disabled' },
                  { label:'Parser',      val: testResult.parser },
                  { label:'Permissions', val: testResult.permissions },
                  { label:'Latency',     val: `${testResult.latency_ms}ms` },
                ].map(({ label, val }) => (
                  <div key={label} className="flex items-center justify-between py-1.5" style={{ borderBottom:'1px solid var(--border)' }}>
                    <span style={{ color:'var(--text-3)' }}>{label}</span>
                    <StatusChip val={val} />
                  </div>
                ))}
              </div>
            )}
          </>
        )}

        {/* ── Alerts ── */}
        {tab === 'alerts' && (
          <div className="space-y-3">
            <p style={{ color:'var(--text-3)' }}>Alerts are triggered when conditions are met for this source.</p>
            {[
              { label:'Source Offline',       active: true },
              { label:'No Logs > 15 min',     active: true },
              { label:'Parser Failures',       active: false },
              { label:'Auth Failures',         active: true },
              { label:'EPS Drops > 50%',      active: false },
              { label:'Queue Full',            active: false },
            ].map(({ label, active }) => (
              <div key={label} className="flex items-center justify-between rounded-lg px-3 py-2.5"
                style={{ background:'var(--glass-bg)', border:'1px solid var(--border)' }}>
                <span style={{ color:'var(--text-2)' }}>{label}</span>
                <div className="flex items-center gap-1.5">
                  <span className="text-[10px]" style={{ color: active ? 'var(--green)' : 'var(--text-3)' }}>{active ? 'Enabled' : 'Disabled'}</span>
                  <div className="h-4 w-8 rounded-full relative cursor-pointer" style={{ background: active ? 'var(--accent)' : 'var(--border)' }}>
                    <div className="absolute top-0.5 h-3 w-3 rounded-full transition-all" style={{ background:'#fff', left: active ? '18px' : '2px' }} />
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}

      </div>
    </div>
  );
}

// ── Pipeline View ─────────────────────────────────────────────────────────────

function PipelineView({ sources }: { sources: LogSource[] }) {
  const stages = [
    { name:'Source',         icon:PlugZap,   desc:`${sources.length} sources configured`,         color:'var(--accent)' },
    { name:'Collector',      icon:Download,  desc:'Syslog :514 · HTTP /api/ingest',               color:'var(--blue)' },
    { name:'Parser',         icon:Code2,     desc:'CEF · Syslog · JSON · WinEvent · Auto',        color:'var(--green)' },
    { name:'Normalizer',     icon:Layers,    desc:'ECS field mapping · field extraction',          color:'var(--yellow)' },
    { name:'Enrichment',     icon:Zap,       desc:'GeoIP · ASN · TI · Asset · User · MITRE',      color:'var(--orange)' },
    { name:'Correlation',    icon:GitBranch, desc:'Rules · Sequences · Time windows',              color:'var(--accent)' },
    { name:'Storage',        icon:HardDrive, desc:'PostgreSQL + compression · 90d hot retention', color:'var(--blue)' },
    { name:'Detection',      icon:Shield,    desc:'Sigma rules · YARA · ML anomaly · IOC match',  color:'var(--red)' },
    { name:'Alert',          icon:Bell,      desc:'Incidents · Playbooks · Notifications',         color:'var(--red)' },
  ];

  return (
    <div className="p-6 space-y-4">
      <p className="text-xs font-semibold" style={{ color:'var(--text-2)' }}>Ingestion Pipeline</p>
      <p className="text-[11px]" style={{ color:'var(--text-3)' }}>Log flow from source to alert. Delays or failures appear here in real-time.</p>
      <div className="flex flex-col items-center gap-0 max-w-md mx-auto">
        {stages.map((s, i) => (
          <div key={s.name} className="w-full flex flex-col items-center">
            <div className="w-full rounded-xl px-4 py-3 flex items-center gap-3"
              style={{ background:'var(--glass-bg)', border:`1px solid ${s.color}44` }}>
              <div className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
                style={{ background:`${s.color}22`, border:`1px solid ${s.color}44` }}>
                <s.icon className="h-4 w-4" style={{ color:s.color }} />
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>{s.name}</p>
                <p className="text-[10px] truncate" style={{ color:'var(--text-3)' }}>{s.desc}</p>
              </div>
              <span className="h-1.5 w-1.5 rounded-full shrink-0 animate-pulse" style={{ background:'var(--green)' }} />
            </div>
            {i < stages.length - 1 && (
              <div className="flex flex-col items-center py-1">
                <div className="w-px h-4" style={{ background:'var(--border)' }} />
                <ArrowRight className="h-3 w-3 rotate-90" style={{ color:'var(--text-3)' }} />
                <div className="w-px h-1" style={{ background:'var(--border)' }} />
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Monitoring View ───────────────────────────────────────────────────────────

function MonitoringView({ monitoring }: { monitoring: MonitoringData | null }) {
  if (!monitoring) return (
    <div className="flex justify-center py-16"><Loader2 className="h-5 w-5 animate-spin" style={{ color:'var(--text-3)' }} /></div>
  );

  return (
    <div className="p-4 space-y-4">
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label:'Total Sources', val: monitoring.total,     color:'var(--text-1)' },
          { label:'Online',        val: monitoring.online,    color:'var(--green)' },
          { label:'Warning',       val: monitoring.warning,   color:'var(--yellow)' },
          { label:'Offline',       val: monitoring.offline,   color:'var(--red)' },
        ].map(s => (
          <div key={s.label} className="g-card px-4 py-3 text-center">
            <p className="text-[10px] uppercase tracking-wider mb-1" style={{ color:'var(--text-3)' }}>{s.label}</p>
            <p className="text-xl font-bold tabular-nums" style={{ color:s.color }}>{s.val}</p>
          </div>
        ))}
      </div>
      <div className="g-card p-3 flex items-center gap-3">
        <Activity className="h-4 w-4 shrink-0" style={{ color:'var(--accent)' }} />
        <span className="text-xs" style={{ color:'var(--text-2)' }}>Total Fleet EPS</span>
        <span className="font-mono font-bold text-lg ml-auto tabular-nums" style={{ color:'var(--accent)' }}>{monitoring.total_eps}</span>
      </div>
      <div className="g-card overflow-hidden">
        <p className="text-[10px] font-bold uppercase tracking-wider px-4 py-2.5" style={{ color:'var(--text-3)', borderBottom:'1px solid var(--border)' }}>Source Status</p>
        {monitoring.sources.map(s => (
          <div key={s.id} className="flex items-center gap-3 px-4 py-2.5" style={{ borderBottom:'1px solid var(--border)' }}>
            <StatusIcon status={s.status} />
            <span className="flex-1 text-xs font-medium truncate" style={{ color:'var(--text-1)' }}>{s.name}</span>
            <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{s.last_event ? timeAgo(s.last_event) : 'never'}</span>
            <span className="text-[10px] font-mono tabular-nums w-16 text-right" style={{ color:'var(--text-3)' }}>{s.event_count.toLocaleString()}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function LogSourcesPage() {
  const [sources,       setSources]       = useState<LogSource[]>([]);
  const [healthMap,     setHealthMap]     = useState<Record<number, SourceHealth>>({});
  const [loading,       setLoading]       = useState(true);
  const [mainTab,       setMainTab]       = useState<MainTab>('sources');
  const [selectedSrc,   setSelectedSrc]   = useState<LogSource | null>(null);
  const [connecting,    setConnecting]    = useState<CatalogEntry | null>(null);
  const [search,        setSearch]        = useState('');
  const [catFilter,     setCatFilter]     = useState('');
  const [subFilter,     setSubFilter]     = useState('');
  const [collapsedCats, setCollapsedCats] = useState<Set<string>>(new Set());
  const [selectedIds,   setSelectedIds]   = useState<Set<number>>(new Set());
  const [bulking,       setBulking]       = useState(false);
  const [monitoring,    setMonitoring]    = useState<MonitoringData | null>(null);
  const [aiInsights,    setAiInsights]    = useState<string[]>([]);
  const [aiLoading,     setAiLoading]     = useState(false);
  const [toast,         setToast]         = useState<string | null>(null);
  const [host,          setHost]          = useState('');
  const [statusFilter,  setStatusFilter]  = useState<string>('');
  const [showFilters,   setShowFilters]   = useState(false);

  const notify = (m: string) => { setToast(m); setTimeout(()=>setToast(null), 3500); };

  useEffect(() => { if (typeof window !== 'undefined') setHost(window.location.hostname); }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await logSourcesAPI.getAll();
      const list: LogSource[] = Array.isArray(r.data) ? r.data : [];
      setSources(list);
      // Load health for each source (max 10 in parallel to avoid hammering)
      const chunk = list.slice(0, 20);
      const results = await Promise.allSettled(chunk.map(s => logSourcesAPI.getHealth(s.id)));
      const map: Record<number, SourceHealth> = {};
      chunk.forEach((s, i) => {
        const r = results[i];
        if (r.status === 'fulfilled' && r.value.data) map[s.id] = r.value.data;
      });
      setHealthMap(map);
    } catch { setSources([]); }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { load(); }, [load]);

  useEffect(() => {
    if (mainTab === 'monitoring') {
      logSourcesAPI.getMonitoring().then(r => r.data && setMonitoring(r.data));
    }
  }, [mainTab]);

  const toggle = async (src: LogSource) => {
    try {
      await logSourcesAPI.update(src.id, { name:src.name, device_type:src.device_type||'', enabled:!src.enabled });
      setSources(p => p.map(s => s.id===src.id ? {...s, enabled:!s.enabled} : s));
      if (selectedSrc?.id === src.id) setSelectedSrc(p => p ? {...p, enabled:!p.enabled} : p);
    } catch { notify('Update failed'); }
  };

  const remove = async (src: LogSource) => {
    if (!confirm(`Delete "${src.name}"? This will stop log ingestion immediately.`)) return;
    try {
      await logSourcesAPI.remove(src.id);
      setSources(p => p.filter(s => s.id !== src.id));
      if (selectedSrc?.id === src.id) setSelectedSrc(null);
      notify('Source deleted');
    } catch { notify('Delete failed'); }
  };

  const bulkAction = async (action: 'enable' | 'disable' | 'delete') => {
    const ids = [...selectedIds];
    if (!ids.length) return;
    if (action === 'delete' && !confirm(`Delete ${ids.length} source(s)?`)) return;
    setBulking(true);
    try {
      await logSourcesAPI.bulk(action, ids);
      setSelectedIds(new Set());
      load();
      notify(`${ids.length} sources ${action}d`);
    } catch { notify('Bulk action failed'); }
    finally { setBulking(false); }
  };

  const loadAI = async () => {
    setAiLoading(true);
    try {
      const r = await logSourcesAPI.aiInsights();
      const insights = r.data?.insights;
      if (typeof insights === 'string') {
        try { setAiInsights(JSON.parse(insights)); } catch { setAiInsights([insights]); }
      } else if (Array.isArray(insights)) {
        setAiInsights(insights);
      }
    } catch { setAiInsights(['AI service unavailable.']); }
    finally { setAiLoading(false); }
  };

  // Sidebar categories with subcategory counts
  const catalogByCategory = useMemo(() => {
    const m = new Map<string, Map<string, CatalogEntry[]>>();
    for (const cat of CAT_ORDER) m.set(cat, new Map());
    for (const e of CATALOG) {
      if (!m.has(e.category)) m.set(e.category, new Map());
      const subs = m.get(e.category)!;
      if (!subs.has(e.subcategory)) subs.set(e.subcategory, []);
      subs.get(e.subcategory)!.push(e);
    }
    return m;
  }, []);

  const activeByType = useMemo(() => {
    const m: Record<string, number> = {};
    for (const s of sources) { const k = s.device_type||''; m[k] = (m[k]??0)+1; }
    return m;
  }, [sources]);

  const filteredSources = useMemo(() => {
    let list = sources;
    if (catFilter) {
      const ids = new Set(CATALOG.filter(e => e.category === catFilter && (!subFilter || e.subcategory === subFilter)).map(e => e.id));
      list = list.filter(s => ids.has(s.device_type||''));
    }
    if (statusFilter) {
      list = list.filter(s => {
        const h = healthMap[s.id];
        const st = h?.status ?? (s.enabled ? 'warning' : 'offline');
        return st === statusFilter;
      });
    }
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(s => s.name.toLowerCase().includes(q) || (s.device_type||'').includes(q) || (s.ip_address||'').includes(q));
    }
    return list;
  }, [sources, catFilter, subFilter, statusFilter, search, healthMap]);

  const filteredMarketplace = useMemo(() => {
    if (!catFilter && !search) return CATALOG;
    return CATALOG.filter(e =>
      (!catFilter || e.category === catFilter) &&
      (!subFilter || e.subcategory === subFilter) &&
      (!search || e.label.toLowerCase().includes(search.toLowerCase()) || e.vendor.toLowerCase().includes(search.toLowerCase()) || e.desc.toLowerCase().includes(search.toLowerCase()))
    );
  }, [catFilter, subFilter, search]);

  const toggleCat = (cat: string) => setCollapsedCats(prev => { const n=new Set(prev); n.has(cat)?n.delete(cat):n.add(cat); return n; });

  const totalOnline  = Object.values(healthMap).filter(h=>h.status==='online').length;
  const totalWarning = Object.values(healthMap).filter(h=>h.status==='warning').length;
  const totalOffline = sources.length - totalOnline - totalWarning;

  return (
    <RootLayout title="Log Sources" subtitle="Connect, monitor, and manage all your data sources">

      {toast && (
        <div className="fixed bottom-4 right-4 z-50 px-4 py-2 rounded-lg text-sm font-medium shadow-lg"
          style={{ background:'var(--accent)', color:'#000' }}>
          {toast}
        </div>
      )}

      {connecting && (
        <ConnectModal def={connecting} host={host}
          onClose={() => setConnecting(null)}
          onCreated={src => { setSources(p=>[...p,src]); setConnecting(null); notify('Source connected'); }} />
      )}

      <div className="flex flex-col gap-4">

        {/* ── Header Bar ── */}
        <div className="g-card px-4 py-3 flex flex-wrap items-center gap-3">
          {/* Search */}
          <div className="relative flex-1 min-w-[180px] max-w-xs">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />
            <input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search sources…"
              className="g-input pl-9 text-xs w-full" />
          </div>

          {/* Health summary pills */}
          <div className="flex items-center gap-2 text-[10px]">
            {[{label:'Online', val:totalOnline, color:'var(--green)'},{label:'Warning', val:totalWarning, color:'var(--yellow)'},{label:'Offline', val:totalOffline, color:'var(--red)'}].map(s=>(
              <button key={s.label} onClick={()=>setStatusFilter(p=>p===s.label.toLowerCase()?'':s.label.toLowerCase())}
                className="flex items-center gap-1 px-2 py-1 rounded-lg transition-colors"
                style={{ background: statusFilter===s.label.toLowerCase() ? `${s.color}22` : 'var(--glass-bg)', border:`1px solid ${statusFilter===s.label.toLowerCase() ? s.color+'44' : 'var(--border)'}`, color:s.color }}>
                <span className="font-bold">{s.val}</span> <span style={{ color:'var(--text-3)' }}>{s.label}</span>
              </button>
            ))}
          </div>

          <div className="flex-1" />

          <div className="flex items-center gap-2">
            {selectedIds.size > 0 && (
              <div className="flex items-center gap-1 pl-2" style={{ borderLeft:'1px solid var(--border)' }}>
                <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{selectedIds.size} selected</span>
                {['enable','disable','delete'].map(a=>(
                  <button key={a} onClick={()=>bulkAction(a as any)} disabled={bulking}
                    className="g-btn g-btn-ghost text-[10px] py-1 px-2 capitalize" style={{ color: a==='delete'?'var(--red)':undefined }}>
                    {bulking ? <Loader2 className="h-3 w-3 animate-spin" /> : a}
                  </button>
                ))}
              </div>
            )}
            <button onClick={load} className="g-btn g-btn-ghost text-xs" title="Refresh">↻</button>
            <button onClick={()=>setMainTab('marketplace')} className="g-btn g-btn-ghost text-xs"><Package className="h-3.5 w-3.5" /> Marketplace</button>
            <button onClick={()=>setConnecting(CATALOG[0])} className="g-btn g-btn-primary text-xs px-4"><Plus className="h-3.5 w-3.5" /> Add Source</button>
          </div>
        </div>

        {/* ── Main Tabs ── */}
        <div className="flex items-center" style={{ borderBottom:'1px solid var(--border)' }}>
          {([
            { id:'sources',     label:'Sources',     icon:Server },
            { id:'marketplace', label:'Marketplace', icon:Package },
            { id:'monitoring',  label:'Monitoring',  icon:Activity },
            { id:'pipeline',    label:'Pipeline',    icon:Workflow },
          ] as const).map(t => (
            <button key={t.id} onClick={()=>setMainTab(t.id)}
              className="flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors"
              style={{ borderColor:mainTab===t.id?'var(--accent)':'transparent', color:mainTab===t.id?'var(--accent)':'var(--text-3)' }}>
              <t.icon className="h-3.5 w-3.5" />
              <span className="hidden sm:inline">{t.label}</span>
            </button>
          ))}
        </div>

        {/* ── Body ── */}
        <div className="flex gap-4 min-h-0">

          {/* Left Category Sidebar */}
          <aside className="hidden lg:flex flex-col w-52 shrink-0 gap-1">
            <button onClick={()=>{setCatFilter('');setSubFilter('');}}
              className="w-full text-left px-3 py-2 rounded-lg text-xs font-medium transition-colors"
              style={{ background:!catFilter?'var(--accent-glow)':'transparent', color:!catFilter?'var(--accent)':'var(--text-2)' }}>
              All Categories ({CATALOG.length})
            </button>
            {CAT_ORDER.map(cat => {
              const Icon = CAT_ICON[cat] ?? Server;
              const color = CAT_COLOR[cat] ?? 'var(--text-3)';
              const subs = catalogByCategory.get(cat);
              const collapsed = collapsedCats.has(cat);
              const catEntries = CATALOG.filter(e=>e.category===cat);
              const activeCount = catEntries.reduce((n,e)=>(activeByType[e.id]??0)+n,0);
              return (
                <div key={cat}>
                  <button onClick={()=>{ if(catFilter===cat && !subFilter){toggleCat(cat);}else{setCatFilter(cat);setSubFilter('');} }}
                    className="w-full text-left px-3 py-2 rounded-lg flex items-center gap-2 transition-colors"
                    style={{ background:catFilter===cat&&!subFilter?`${color}18`:'transparent', color:catFilter===cat&&!subFilter?color:'var(--text-2)' }}>
                    <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
                    <span className="flex-1 text-xs font-medium truncate">{cat}</span>
                    {activeCount > 0 && <span className="text-[9px] font-mono" style={{ color:'var(--accent)' }}>{activeCount}</span>}
                    {collapsed ? <ChevronRight className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} /> : <ChevronDown className="h-3 w-3 shrink-0" style={{ color:'var(--text-3)' }} />}
                  </button>
                  {!collapsed && subs && Array.from(subs.keys()).map(sub => (
                    <button key={sub} onClick={()=>{ setCatFilter(cat); setSubFilter(sub); }}
                      className="w-full text-left pl-8 pr-3 py-1.5 rounded-lg text-[11px] transition-colors flex items-center gap-1.5"
                      style={{ background:subFilter===sub&&catFilter===cat?`${color}15`:'transparent', color:subFilter===sub&&catFilter===cat?color:'var(--text-3)' }}>
                      <span className="h-1 w-1 rounded-full shrink-0" style={{ background:subFilter===sub&&catFilter===cat?color:'var(--text-3)' }} />
                      <span className="truncate">{sub}</span>
                    </button>
                  ))}
                </div>
              );
            })}
          </aside>

          {/* Main content + detail panel */}
          <div className="flex-1 min-w-0 flex gap-4">

            {/* Content area */}
            <div className={`flex-1 min-w-0 ${selectedSrc ? 'hidden lg:block' : ''}`}>

              {/* ── Sources Tab ── */}
              {mainTab === 'sources' && (
                loading ? (
                  <div className="flex justify-center py-16"><Loader2 className="h-5 w-5 animate-spin" style={{ color:'var(--text-3)' }} /></div>
                ) : filteredSources.length === 0 ? (
                  <div className="g-card p-16 text-center space-y-3">
                    <PlugZap className="h-10 w-10 mx-auto opacity-20" style={{ color:'var(--text-3)' }} />
                    <p className="text-sm font-medium" style={{ color:'var(--text-2)' }}>{sources.length === 0 ? 'No sources connected yet' : 'No sources match filters'}</p>
                    <button onClick={()=>setMainTab('marketplace')} className="g-btn g-btn-primary text-xs mx-auto">
                      <Package className="h-3.5 w-3.5" /> Browse Marketplace
                    </button>
                  </div>
                ) : (
                  <div className="g-card overflow-hidden">
                    {/* Select all */}
                    <div className="flex items-center gap-3 px-4 py-2.5" style={{ borderBottom:'1px solid var(--border)', background:'var(--glass-bg)' }}>
                      <button onClick={() => setSelectedIds(p=>p.size===filteredSources.length ? new Set() : new Set(filteredSources.map(s=>s.id)))}>
                        {selectedIds.size === filteredSources.length && filteredSources.length > 0
                          ? <CheckSquare className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
                          : <Square className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}
                      </button>
                      <span className="text-[10px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>
                        {filteredSources.length} source{filteredSources.length!==1?'s':''}
                      </span>
                    </div>
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs">
                        <thead>
                          <tr style={{ borderBottom:'1px solid var(--border)' }}>
                            {['','Name','Type','Transport','Address / Key','Events','Last Event','Health',''].map((h,i)=>(
                              <th key={i} className="text-left px-4 py-2.5 text-[10px] font-semibold uppercase tracking-wider shrink-0" style={{ color:'var(--text-3)' }}>{h}</th>
                            ))}
                          </tr>
                        </thead>
                        <tbody>
                          {filteredSources.map(src => {
                            const def    = CATALOG.find(d=>d.id===src.device_type);
                            const Icon   = def?.Icon ?? Server;
                            const color  = def?.color ?? 'var(--text-3)';
                            const health = healthMap[src.id];
                            const status = health?.status ?? (src.enabled ? 'warning' : 'offline');
                            return (
                              <tr key={src.id}
                                className="hover:bg-[rgba(255,255,255,0.02)] transition-colors cursor-pointer"
                                style={{ borderBottom:'1px solid var(--border)', background:selectedSrc?.id===src.id?'var(--accent-glow)':undefined }}
                                onClick={()=>setSelectedSrc(src)}>
                                <td className="px-4 py-3" onClick={e=>e.stopPropagation()}>
                                  <button onClick={()=>setSelectedIds(p=>{ const n=new Set(p); n.has(src.id)?n.delete(src.id):n.add(src.id); return n; })}>
                                    {selectedIds.has(src.id)
                                      ? <CheckSquare className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
                                      : <Square className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}
                                  </button>
                                </td>
                                <td className="px-4 py-3">
                                  <div className="flex items-center gap-2">
                                    <div className="h-6 w-6 rounded-lg flex items-center justify-center shrink-0" style={{ background:`${color}15`, border:`1px solid ${color}30` }}>
                                      <Icon className="h-3 w-3" style={{ color }} />
                                    </div>
                                    <span className="font-medium" style={{ color:'var(--text-1)' }}>{src.name}</span>
                                  </div>
                                </td>
                                <td className="px-4 py-3" style={{ color:'var(--text-2)' }}>{def?.label ?? src.device_type ?? '—'}</td>
                                <td className="px-4 py-3">
                                  <span className="text-[10px] px-2 py-0.5 rounded font-mono uppercase" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-3)' }}>
                                    {src.source_type}
                                  </span>
                                </td>
                                <td className="px-4 py-3 font-mono text-[11px]" style={{ color:'var(--text-3)' }}>
                                  {src.source_type==='syslog' ? (src.ip_address||<span className="italic">any</span>) : (src.api_key_hint?`…${src.api_key_hint}`:'—')}
                                </td>
                                <td className="px-4 py-3 font-mono tabular-nums" style={{ color:'var(--text-2)' }}>{src.event_count.toLocaleString()}</td>
                                <td className="px-4 py-3" style={{ color:'var(--text-3)' }}>{src.last_event ? timeAgo(src.last_event) : '—'}</td>
                                <td className="px-4 py-3"><StatusBadge status={status} /></td>
                                <td className="px-4 py-3" onClick={e=>e.stopPropagation()}>
                                  <div className="flex items-center gap-1">
                                    <button onClick={()=>toggle(src)} className="p-1.5 rounded hover:bg-[var(--glass-hover)]" style={{ color:'var(--text-3)' }}>
                                      {src.enabled ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                                    </button>
                                    <button onClick={()=>remove(src)} className="p-1.5 rounded" style={{ color:'var(--text-3)' }}>
                                      <Trash2 className="h-3.5 w-3.5" />
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )
              )}

              {/* ── Marketplace Tab ── */}
              {mainTab === 'marketplace' && (
                <div className="space-y-6">
                  {CAT_ORDER.map(cat => {
                    const defs = filteredMarketplace.filter(e=>e.category===cat);
                    if (!defs.length) return null;
                    const color = CAT_COLOR[cat] ?? 'var(--text-2)';
                    return (
                      <div key={cat}>
                        <div className="flex items-center gap-2 mb-3">
                          <span className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background:color }} />
                          <p className="text-[11px] font-bold uppercase tracking-wider" style={{ color:'var(--text-3)' }}>{cat}</p>
                          <div className="flex-1 h-px" style={{ background:'var(--border)' }} />
                          <span className="text-[10px]" style={{ color:'var(--text-3)' }}>{defs.length}</span>
                        </div>
                        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                          {defs.map(def => {
                            const existing = activeByType[def.id] ?? 0;
                            return (
                              <div key={def.id} className="g-card p-4 flex flex-col gap-3 hover:border-[var(--accent-border)] transition-colors">
                                <div className="flex items-start gap-3">
                                  <div className="h-9 w-9 rounded-xl flex items-center justify-center shrink-0" style={{ background:`${def.color}15`, border:`1px solid ${def.color}30` }}>
                                    <def.Icon className="h-5 w-5" style={{ color:def.color }} />
                                  </div>
                                  <div className="flex-1 min-w-0">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <p className="text-xs font-semibold" style={{ color:'var(--text-1)' }}>{def.label}</p>
                                      {existing > 0 && (
                                        <span className="text-[9px] px-1.5 py-0.5 rounded-full font-medium" style={{ background:'var(--accent-glow)', color:'var(--accent)', border:'1px solid var(--accent-border)' }}>{existing} active</span>
                                      )}
                                    </div>
                                    <p className="text-[10px] leading-snug mt-0.5" style={{ color:'var(--text-3)' }}>{def.vendor}</p>
                                  </div>
                                </div>
                                <p className="text-[11px] leading-relaxed" style={{ color:'var(--text-3)' }}>{def.desc}</p>
                                <div className="flex flex-wrap gap-1">
                                  {def.collection_methods.slice(0,3).map(m=>(
                                    <span key={m} className="text-[9px] px-1.5 py-0.5 rounded font-mono" style={{ background:'var(--glass-bg)', border:'1px solid var(--border)', color:'var(--text-3)' }}>{m}</span>
                                  ))}
                                </div>
                                <button onClick={()=>setConnecting(def)} className="g-btn g-btn-primary text-xs w-full justify-center mt-auto">
                                  <Plus className="h-3.5 w-3.5" /> Connect
                                </button>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}

              {/* ── Monitoring Tab ── */}
              {mainTab === 'monitoring' && <MonitoringView monitoring={monitoring} />}

              {/* ── Pipeline Tab ── */}
              {mainTab === 'pipeline' && <PipelineView sources={sources} />}

            </div>

            {/* Source Detail Panel */}
            {selectedSrc && (
              <div className="w-full lg:w-80 xl:w-96 shrink-0 flex flex-col g-card overflow-hidden" style={{ maxHeight:'calc(100vh - 200px)' }}>
                <SourceDetailPanel
                  src={selectedSrc}
                  def={CATALOG.find(d=>d.id===selectedSrc.device_type)}
                  host={host}
                  onClose={()=>setSelectedSrc(null)}
                  onToggle={()=>toggle(selectedSrc)}
                  onDelete={()=>remove(selectedSrc)}
                />
              </div>
            )}
          </div>
        </div>

        {/* ── AI Insights ── */}
        <div className="g-card overflow-hidden">
          <button className="w-full flex items-center gap-2 px-4 py-3 hover:bg-[var(--glass-hover)] transition-colors"
            onClick={aiInsights.length===0 ? loadAI : ()=>setAiInsights([])}>
            <Bot className="h-3.5 w-3.5" style={{ color:'var(--accent)' }} />
            <span className="text-xs font-semibold" style={{ color:'var(--text-2)' }}>AI Source Insights</span>
            <div className="flex-1" />
            {aiLoading ? <Loader2 className="h-3.5 w-3.5 animate-spin" style={{ color:'var(--text-3)' }} /> : <Zap className="h-3.5 w-3.5" style={{ color:'var(--text-3)' }} />}
          </button>
          {aiInsights.length > 0 && (
            <div className="px-4 pb-4 space-y-2">
              {aiInsights.map((ins, i) => (
                <div key={i} className="flex items-start gap-2 rounded-lg px-3 py-2.5"
                  style={{ background:'var(--glass-bg)', border:'1px solid var(--accent-border)' }}>
                  <Info className="h-3.5 w-3.5 shrink-0 mt-0.5" style={{ color:'var(--accent)' }} />
                  <p className="text-xs leading-relaxed" style={{ color:'var(--text-2)' }}>{ins}</p>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* ── Receiver Endpoints card ── */}
        <div className="g-card p-4 space-y-3">
          <p className="text-xs font-semibold" style={{ color:'var(--text-2)' }}>Receiver Endpoints</p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <p className="text-[10px] mb-1.5" style={{ color:'var(--text-3)' }}>Syslog (UDP / TCP / TLS)</p>
              <CodeBlock code={`<host>:514   UDP\n<host>:514   TCP\n<host>:6514  TLS`} host={host} />
            </div>
            <div>
              <p className="text-[10px] mb-1.5" style={{ color:'var(--text-3)' }}>HTTP Ingest (REST / Webhook)</p>
              <CodeBlock code={`POST https://<host>/api/ingest\nX-Api-Key: <key>\nContent-Type: application/json\n\nMax: 10 MB · 5,000 events / request`} host={host} />
            </div>
          </div>
        </div>

      </div>
    </RootLayout>
  );
}
