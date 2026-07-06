-- Rollback migration 059: remove the v2 Sigma rule pack (51 rules).
-- Only deletes the specific rules added in this migration; rules from
-- migration 056 are unaffected.

DO $$
DECLARE v_t INT := 1;
BEGIN
DELETE FROM sigma_rules WHERE tenant_id = v_t AND title IN (
  -- Execution — LOLBins
  'CertUtil Used to Download or Decode File',
  'Mshta Remote Content Execution',
  'Regsvr32 COM Scriptlet Abuse',
  'Odbcconf DLL Registration Abuse',
  -- Persistence
  'Registry Run Key Persistence',
  'WMI Event Subscription for Persistence',
  'BITS Job Used for Persistence or Download',
  'Browser Extension Installed from Unusual Path',
  'DLL Sideloading from User-Writable Path',
  -- Defense Evasion
  'AMSI Bypass Technique Detected',
  'UAC Bypass via Fodhelper or Eventvwr',
  'Windows Firewall Disabled',
  'Timestomping — File Timestamp Manipulation',
  'Process Hollowing or RunPE Indicators',
  -- Credential Access
  'AWS Credentials File Accessed',
  'Cloud Instance Metadata SSRF',
  'AS-REP Roasting Attack',
  'Private Key or Credential File Accessed on Linux',
  -- Discovery
  'System and Identity Discovery Commands',
  'Process and Network Connection Discovery',
  'File and Directory Discovery via Find or Dir',
  'Cloud Environment Discovery',
  -- Lateral Movement
  'WMI Remote Lateral Movement',
  'Remote Desktop Session Hijacking via tscon',
  'DCOM Lateral Movement',
  'SSH ProxyJump or ProxyCommand Lateral Movement',
  -- Collection
  'Clipboard Data Access',
  'Screenshot Capture Tool Executed',
  'Email Archive or PST File Accessed',
  -- Command and Control
  'Ngrok Tunnel Detected',
  'Chisel Proxy Tunnel Tool',
  'Sliver or Havoc C2 Framework Indicators',
  'TOR Browser or Anonymous Proxy Usage',
  'Metasploit Framework Indicators',
  -- Exfiltration
  'FTP or SCP Data Exfiltration',
  'Rclone or Megatools Cloud Exfiltration',
  'ICMP Tunneling for Data Exfiltration',
  -- Cloud
  'AWS CloudTrail Logging Disabled or Deleted',
  'AWS S3 Bucket Made Public',
  'AWS IAM Privilege Escalation',
  'Azure Service Principal Credential Reset',
  'GCP Service Account Key Exported',
  'Cloud Compute Instance Created in New Region',
  -- Container / Kubernetes
  'Docker Socket Accessed from Container',
  'Kubectl Exec Into Running Pod',
  'Kubernetes ClusterRoleBinding to cluster-admin',
  'Kubernetes Secrets Enumeration',
  -- Supply Chain / Reconnaissance
  'DNS Zone Transfer Attempt',
  'Malicious npm or pip Package Install Pattern',
  'npm postinstall Script Downloading Remote Content',
  'Dependency Confusion Attack Pattern',
  -- Impact / Web / Additional
  'Cryptocurrency Mining Indicators',
  'Container or VM Escape via OverlayFS',
  'SQL Injection Pattern in Web Logs',
  'Cross-Site Scripting (XSS) Attempt in Web Logs',
  'Path Traversal Attack Detected',
  'Server-Side Request Forgery (SSRF) Attempt',
  'Phishing Email Attachment Opened',
  'Suspicious Office Macro Execution'
);
END $$;
