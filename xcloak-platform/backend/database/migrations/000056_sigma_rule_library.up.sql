-- Migration 056: Seed production-quality Sigma rule library for tenant 1.
-- All rules use IF NOT EXISTS guards (match on title + tenant_id) so the
-- migration is safe to re-run if interrupted. Rules cover the 12 MITRE
-- ATT&CK tactics most commonly seen in SOC environments.
--
-- Keywords array semantics:
--   plain string        → case-insensitive substring match on full log message
--   "field|mod:value"   → field-level match (requires parsed_fields)
--   __ALL__ prefix      → all keywords must match (AND instead of OR)

DO $$
DECLARE v_t INT := 1; -- default tenant
BEGIN

-- ── INITIAL ACCESS ────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'SSH Brute Force Login Attempts',
  'Detects rapid failed SSH authentication attempts indicative of a brute-force attack.',
  'high','Initial Access','T1110.001','Brute Force: Password Guessing',
  'authentication','linux','sshd','stable',
  '["attack.initial_access","attack.t1110.001"]','["Legitimate penetration tests","Misconfigured backup tools"]',
  '["https://attack.mitre.org/techniques/T1110/001/"]',
  '["Failed password","Invalid user","authentication failure","Connection closed by authenticating user","Disconnected from authenticating user"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='SSH Brute Force Login Attempts' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'RDP Brute Force via Windows Event Log',
  'Detects multiple failed RDP authentication events (EventID 4625) from the same source.',
  'high','Initial Access','T1110.001','Brute Force: Password Guessing',
  'authentication','windows','','stable',
  '["attack.initial_access","attack.t1110.001"]','["Legitimate admin login failures","Password expiry"]',
  '["https://attack.mitre.org/techniques/T1110/001/"]',
  '["EventID|exact:4625","LogonType|exact:10"]',
  '{"auth_fail":["EventID|exact:4625"],"rdp":["LogonType|exact:10"]}','auth_fail and rdp',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='RDP Brute Force via Windows Event Log' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Web Shell Upload Detected',
  'Detects indicators of web shell file upload or execution via common web server logs.',
  'critical','Initial Access','T1190','Exploit Public-Facing Application',
  'webserver','','','stable',
  '["attack.initial_access","attack.t1190"]','["Authorized red-team exercises"]',
  '["https://attack.mitre.org/techniques/T1190/"]',
  '["cmd.exe","/bin/sh","/bin/bash","eval(base64_decode","eval(gzinflate","passthru(","system(","exec(","shell_exec(","phpinfo()"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Web Shell Upload Detected' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Log4Shell Exploitation Attempt',
  'Detects Log4j JNDI injection patterns in HTTP requests (CVE-2021-44228).',
  'critical','Initial Access','T1190','Exploit Public-Facing Application',
  'webserver','','','stable',
  '["attack.initial_access","attack.t1190","cve.2021.44228"]','["Security scanners","WAF test traffic"]',
  '["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]',
  '["${jndi:ldap","${jndi:rmi","${jndi:dns","${${lower:j}ndi","${${::-j}${::-n}${::-d}${::-i}"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Log4Shell Exploitation Attempt' AND tenant_id=v_t);

-- ── EXECUTION ─────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'PowerShell Encoded Command Execution',
  'Detects PowerShell launched with an encoded/obfuscated command, a common malware technique.',
  'high','Execution','T1059.001','Command and Scripting Interpreter: PowerShell',
  'process_creation','windows','','stable',
  '["attack.execution","attack.t1059.001"]','["Legitimate admin scripts","Software deployment tools"]',
  '["https://attack.mitre.org/techniques/T1059/001/"]',
  '["powershell -enc","powershell -e ","powershell -encodedcommand","powershell.exe -enc","powershell -nop -w hidden -enc","powershell -noninteractive -enc"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='PowerShell Encoded Command Execution' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'PowerShell Download Cradle',
  'Detects PowerShell downloading and executing remote content — classic stager pattern.',
  'high','Execution','T1059.001','Command and Scripting Interpreter: PowerShell',
  'process_creation','windows','','stable',
  '["attack.execution","attack.t1059.001"]','["Software distribution via PS","SCCM scripts"]',
  '["https://attack.mitre.org/techniques/T1059/001/"]',
  '["IEX (New-Object Net.WebClient)","IEX(New-Object","Invoke-Expression (New-Object","(New-Object System.Net.WebClient).DownloadString","DownloadFile","DownloadString","Net.WebClient","WebRequest","curl -UseBasicParsing"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='PowerShell Download Cradle' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Suspicious WMIC Remote Execution',
  'Detects WMIC used for remote process creation — commonly abused for lateral movement.',
  'high','Execution','T1047','Windows Management Instrumentation',
  'process_creation','windows','','stable',
  '["attack.execution","attack.t1047"]','["Legitimate remote administration"]',
  '["https://attack.mitre.org/techniques/T1047/"]',
  '["wmic /node:","wmic process call create","wmic os get","wmic shadowcopy delete","wmic /user:","WmiPrvSE.exe"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Suspicious WMIC Remote Execution' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Linux Bash Reverse Shell',
  'Detects common bash reverse shell one-liners in command execution logs.',
  'critical','Execution','T1059.004','Command and Scripting Interpreter: Unix Shell',
  'process_creation','linux','','stable',
  '["attack.execution","attack.t1059.004"]','["CTF/security training environments"]',
  '["https://attack.mitre.org/techniques/T1059/004/"]',
  '["bash -i >& /dev/tcp","bash -i >&/dev/tcp","0>&1","exec /bin/bash","0<&196","exec 196<>/dev/tcp","bash -c {echo","sh -i >& /dev/tcp"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Linux Bash Reverse Shell' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Python Reverse Shell or Exec',
  'Detects Python used to spawn shells or execute OS commands — common post-exploitation pattern.',
  'high','Execution','T1059.006','Command and Scripting Interpreter: Python',
  'process_creation','linux','','stable',
  '["attack.execution","attack.t1059.006"]','["Legitimate Python scripts with shell calls"]',
  '["https://attack.mitre.org/techniques/T1059/006/"]',
  '["python -c \"import socket","python3 -c \"import socket","import pty; pty.spawn","os.system(\"/bin/sh\")","subprocess.call([\"/bin/sh","-c __import__(''os'').system"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Python Reverse Shell or Exec' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Scheduled Task Created via schtasks',
  'Detects creation of scheduled tasks used for persistence or delayed execution.',
  'medium','Execution','T1053.005','Scheduled Task/Job: Scheduled Task',
  'process_creation','windows','','stable',
  '["attack.execution","attack.persistence","attack.t1053.005"]','["Legitimate software installers","IT automation tools"]',
  '["https://attack.mitre.org/techniques/T1053/005/"]',
  '["schtasks /create","schtasks.exe /create","SchTasks.exe /Create","at.exe \\\\","at /interactive"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Scheduled Task Created via schtasks' AND tenant_id=v_t);

-- ── PERSISTENCE ───────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'New Cron Job Added on Linux',
  'Detects new cron job entries written to system or user crontab files.',
  'medium','Persistence','T1053.003','Scheduled Task/Job: Cron',
  'file_event','linux','','stable',
  '["attack.persistence","attack.t1053.003"]','["Legitimate software installing cron jobs","Monitoring agents"]',
  '["https://attack.mitre.org/techniques/T1053/003/"]',
  '["/etc/cron","crontab -e","crontab -l","CRON","cron.d/","cron.hourly","cron.daily","cron.weekly"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='New Cron Job Added on Linux' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'New Systemd Service Installed',
  'Detects creation or enablement of new systemd services which may indicate persistence.',
  'medium','Persistence','T1543.002','Create or Modify System Process: Systemd Service',
  'file_event','linux','','stable',
  '["attack.persistence","attack.t1543.002"]','["Legitimate software installation","Package manager operations"]',
  '["https://attack.mitre.org/techniques/T1543/002/"]',
  '["systemctl enable","systemctl daemon-reload","Created symlink","systemd/system/","systemctl start","ExecStart="]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='New Systemd Service Installed' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'SSH Authorized Keys Modification',
  'Detects writes to SSH authorized_keys files, which attackers use for persistent access.',
  'high','Persistence','T1098.004','Account Manipulation: SSH Authorized Keys',
  'file_event','linux','','stable',
  '["attack.persistence","attack.t1098.004"]','["Legitimate admin adding SSH keys","Automation/Ansible"]',
  '["https://attack.mitre.org/techniques/T1098/004/"]',
  '["authorized_keys","authorized_keys2",".ssh/authorized"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='SSH Authorized Keys Modification' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'New Local User Account Created',
  'Detects creation of new local user accounts, which may indicate attacker-controlled backdoor accounts.',
  'medium','Persistence','T1136.001','Create Account: Local Account',
  'process_creation','','','stable',
  '["attack.persistence","attack.t1136.001"]','["Legitimate user provisioning","System setup scripts"]',
  '["https://attack.mitre.org/techniques/T1136/001/"]',
  '["useradd ","adduser ","net user /add","New-LocalUser","dsadd user","EventID|exact:4720"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='New Local User Account Created' AND tenant_id=v_t);

-- ── PRIVILEGE ESCALATION ──────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Sudo Privilege Escalation to Root',
  'Detects users escalating to root via sudo — particularly sudo su, sudo bash, sudo -i.',
  'medium','Privilege Escalation','T1548.003','Abuse Elevation Control Mechanism: Sudo and Sudo Caching',
  'process_creation','linux','sudo','stable',
  '["attack.privilege_escalation","attack.t1548.003"]','["Legitimate admin sudo usage"]',
  '["https://attack.mitre.org/techniques/T1548/003/"]',
  '["sudo su","sudo -s","sudo bash","sudo /bin/bash","sudo /bin/sh","sudo -i","TTY=","sudo: pam_authenticate"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Sudo Privilege Escalation to Root' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'SUID / SGID Binary Execution',
  'Detects execution of uncommon SUID or SGID binaries that may allow privilege escalation.',
  'high','Privilege Escalation','T1548.001','Abuse Elevation Control Mechanism: Setuid and Setgid',
  'process_creation','linux','','stable',
  '["attack.privilege_escalation","attack.t1548.001"]','["Legitimate package management","Authorized admin tools"]',
  '["https://attack.mitre.org/techniques/T1548/001/"]',
  '["chmod u+s","chmod +s","chmod 4755","chmod 6755","find / -perm -4000","find / -perm /u=s"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='SUID / SGID Binary Execution' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Windows Token Impersonation',
  'Detects token duplication and impersonation patterns used for privilege escalation.',
  'high','Privilege Escalation','T1134','Access Token Manipulation',
  'process_creation','windows','','stable',
  '["attack.privilege_escalation","attack.t1134"]','["Legitimate security tools","Antivirus products"]',
  '["https://attack.mitre.org/techniques/T1134/"]',
  '["DuplicateTokenEx","ImpersonateLoggedOnUser","CreateProcessWithTokenW","AdjustTokenPrivileges","SeDebugPrivilege","SE_PRIVILEGE_ENABLED"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Windows Token Impersonation' AND tenant_id=v_t);

-- ── DEFENSE EVASION ───────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Windows Security Log Cleared',
  'Detects clearing of the Windows Security or System event log — common before ransomware deployment.',
  'high','Defense Evasion','T1070.001','Indicator Removal: Clear Windows Event Logs',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1070.001"]','["Legitimate log rotation"]',
  '["https://attack.mitre.org/techniques/T1070/001/"]',
  '["wevtutil cl","wevtutil clear-log","EventID|exact:1102","EventID|exact:104","auditpol /clear","Clear-EventLog","Remove-EventLog"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Windows Security Log Cleared' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Linux Audit Log Tampered',
  'Detects attempts to stop, disable, or clear the Linux audit daemon and its logs.',
  'high','Defense Evasion','T1070','Indicator Removal',
  'process_creation','linux','','stable',
  '["attack.defense_evasion","attack.t1070"]','["Planned log rotation by admin","Audit daemon restart during maintenance"]',
  '["https://attack.mitre.org/techniques/T1070/"]',
  '["service auditd stop","systemctl stop auditd","auditd -s disable","truncate -s 0 /var/log/audit","rm /var/log/audit","shred /var/log"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Linux Audit Log Tampered' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Suspicious Rundll32 Process Injection',
  'Detects rundll32 launching DLLs from unusual paths or with suspicious arguments.',
  'high','Defense Evasion','T1218.011','System Binary Proxy Execution: Rundll32',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1218.011"]','["Legitimate software using rundll32"]',
  '["https://attack.mitre.org/techniques/T1218/011/"]',
  '["rundll32 javascript:","rundll32.exe javascript:","rundll32 vbscript:","rundll32 shell32","rundll32.exe ..,","shell32.dll,Control_RunDLL","url.dll,OpenURL","mshtml,RunHTMLApplication"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Suspicious Rundll32 Process Injection' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Security Tool Process Killed',
  'Detects attempts to terminate antivirus, EDR, or security monitoring processes.',
  'high','Defense Evasion','T1562.001','Impair Defenses: Disable or Modify Tools',
  'process_creation','','','stable',
  '["attack.defense_evasion","attack.t1562.001"]','["Legitimate AV uninstall by admin"]',
  '["https://attack.mitre.org/techniques/T1562/001/"]',
  '["taskkill /im msseces.exe","taskkill /im msmpeng.exe","taskkill /im avp.exe","taskkill /im bdagent.exe","sc stop WinDefend","sc stop MBAMService","pkill -f crowdstrike","pkill -f sentinel"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Security Tool Process Killed' AND tenant_id=v_t);

-- ── CREDENTIAL ACCESS ─────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Shadow Password File Access',
  'Detects read access to /etc/shadow which contains hashed Linux user passwords.',
  'critical','Credential Access','T1003.008','OS Credential Dumping: /etc/passwd and /etc/shadow',
  'file_event','linux','','stable',
  '["attack.credential_access","attack.t1003.008"]','["Backup software","Authorized security audits"]',
  '["https://attack.mitre.org/techniques/T1003/008/"]',
  '["cat /etc/shadow","unshadow /etc/passwd","john --wordlist","hashcat -m 1800","/etc/shadow","copy /etc/shadow","less /etc/shadow","tail /etc/shadow"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Shadow Password File Access' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Mimikatz Credential Dumping',
  'Detects Mimikatz signatures in process arguments or log output.',
  'critical','Credential Access','T1003.001','OS Credential Dumping: LSASS Memory',
  'process_creation','windows','','stable',
  '["attack.credential_access","attack.t1003.001"]','["Authorized red-team use"]',
  '["https://attack.mitre.org/techniques/T1003/001/"]',
  '["sekurlsa::logonpasswords","sekurlsa::wdigest","lsadump::sam","lsadump::dcsync","privilege::debug","mimikatz","mimilib","Invoke-Mimikatz","DumpCreds","SafetyKatz"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Mimikatz Credential Dumping' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'LSASS Memory Dump via ProcDump or TaskMgr',
  'Detects dumping of LSASS process memory using ProcDump, Task Manager, or WER.',
  'critical','Credential Access','T1003.001','OS Credential Dumping: LSASS Memory',
  'process_creation','windows','','stable',
  '["attack.credential_access","attack.t1003.001"]','["Authorized security testing"]',
  '["https://attack.mitre.org/techniques/T1003/001/"]',
  '["procdump -ma lsass","procdump.exe -ma lsass","procdump -accepteula -ma lsass","comsvcs.dll MiniDump","lsass.dmp","lsass.exe","Out-Minidump","createdump.exe"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='LSASS Memory Dump via ProcDump or TaskMgr' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Windows SAM Database Dump',
  'Detects copying the SAM registry hive or using reg save to extract local credential hashes.',
  'critical','Credential Access','T1003.002','OS Credential Dumping: Security Account Manager',
  'process_creation','windows','','stable',
  '["attack.credential_access","attack.t1003.002"]','["Authorized penetration test","Backup software accessing registry"]',
  '["https://attack.mitre.org/techniques/T1003/002/"]',
  '["reg save hklm\\sam","reg save HKLM\\SAM","reg save hklm\\security","reg save HKLM\\SYSTEM","copy \\windows\\system32\\config\\sam","esentutl /y /vss"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Windows SAM Database Dump' AND tenant_id=v_t);

-- ── DISCOVERY ─────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Network Port Scan Detected',
  'Detects nmap or other port scanners performing reconnaissance against internal hosts.',
  'medium','Discovery','T1046','Network Service Discovery',
  'process_creation','','','stable',
  '["attack.discovery","attack.t1046"]','["Authorized vulnerability scans","Network monitoring tools"]',
  '["https://attack.mitre.org/techniques/T1046/"]',
  '["nmap -sV","nmap -sS","nmap -sN","nmap -A","masscan --rate","masscan -p","unicornscan","zmap -p","rustscan","nmap -Pn"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Network Port Scan Detected' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Active Directory Enumeration',
  'Detects tools querying Active Directory for users, groups, and GPOs during reconnaissance.',
  'medium','Discovery','T1087.002','Account Discovery: Domain Account',
  'process_creation','windows','','stable',
  '["attack.discovery","attack.t1087.002"]','["Legitimate AD management tools","Help desk operations"]',
  '["https://attack.mitre.org/techniques/T1087/002/"]',
  '["net group /domain","net user /domain","dsquery user","dsquery group","Get-ADUser","Get-ADGroup","Get-ADDomain","BloodHound","SharpHound","PowerView","Invoke-ACLScanner"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Active Directory Enumeration' AND tenant_id=v_t);

-- ── LATERAL MOVEMENT ──────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'PsExec Remote Execution',
  'Detects PsExec or PsExec-like tools used for lateral movement via remote service creation.',
  'high','Lateral Movement','T1021.002','Remote Services: SMB/Windows Admin Shares',
  'process_creation','windows','','stable',
  '["attack.lateral_movement","attack.t1021.002"]','["Authorized remote administration","IT helpdesk tools"]',
  '["https://attack.mitre.org/techniques/T1021/002/"]',
  '["psexec \\\\","PsExec.exe","PSEXESVC","psexesvc","paexec","remcom","csexec","EventID|exact:7045"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='PsExec Remote Execution' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Pass-the-Hash Attack',
  'Detects pass-the-hash authentication patterns where NTLM authentication succeeds with a hash.',
  'critical','Lateral Movement','T1550.002','Use Alternate Authentication Material: Pass the Hash',
  'authentication','windows','','stable',
  '["attack.lateral_movement","attack.t1550.002"]','["Legitimate NTLM authentication in enterprise environments"]',
  '["https://attack.mitre.org/techniques/T1550/002/"]',
  '["sekurlsa::pth","pth-winexe","Invoke-TheHash","pth-net","Overpass-the-Hash","EventID|exact:4624","LogonType|exact:9"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Pass-the-Hash Attack' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Kerberoasting Attack',
  'Detects requests for service tickets (TGS) for service accounts — Kerberoasting technique.',
  'high','Credential Access','T1558.003','Steal or Forge Kerberos Tickets: Kerberoasting',
  'authentication','windows','','stable',
  '["attack.credential_access","attack.t1558.003"]','["Legitimate Kerberos service ticket requests"]',
  '["https://attack.mitre.org/techniques/T1558/003/"]',
  '["Invoke-Kerberoast","Get-DomainSPNTicket","Rubeus kerberoast","EventID|exact:4769","TicketEncryptionType|exact:0x17","ServiceName|contains:$"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Kerberoasting Attack' AND tenant_id=v_t);

-- ── COLLECTION ────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Sensitive Directory Archived for Exfiltration',
  'Detects archiving of sensitive directories (home, etc, var) using tar, zip, or 7z.',
  'high','Collection','T1560.001','Archive Collected Data: Archive via Utility',
  'process_creation','linux','','stable',
  '["attack.collection","attack.t1560.001"]','["Legitimate backups","IT disaster recovery scripts"]',
  '["https://attack.mitre.org/techniques/T1560/001/"]',
  '["tar -czf /tmp","tar czf /dev/tcp","zip -r /tmp","7z a /tmp","tar --exclude","tar cvzf","zip /tmp/dump","zip /var/tmp"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Sensitive Directory Archived for Exfiltration' AND tenant_id=v_t);

-- ── COMMAND AND CONTROL ───────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Base64 Encoded Payload in curl / wget',
  'Detects curl or wget commands downloading base64-encoded content for in-memory execution.',
  'high','Command and Control','T1132.001','Data Encoding: Standard Encoding',
  'process_creation','linux','','stable',
  '["attack.command_and_control","attack.t1132.001"]','["Legitimate base64-encoded config downloads"]',
  '["https://attack.mitre.org/techniques/T1132/001/"]',
  '["curl.*base64","wget.*base64","| base64 -d","|base64 -d","base64 -d |","base64 --decode |","| base64 --decode","echo * | base64"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Base64 Encoded Payload in curl / wget' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'DNS Tunneling Indicators',
  'Detects DNS queries with abnormally long or encoded subdomains used for C2 or data exfiltration.',
  'high','Command and Control','T1071.004','Application Layer Protocol: DNS',
  'dns','','','stable',
  '["attack.command_and_control","attack.t1071.004","attack.exfiltration"]','["Legitimate long domain names","CDN providers"]',
  '["https://attack.mitre.org/techniques/T1071/004/"]',
  '["iodine","dns2tcp","dnscat","dnscat2","nstx","heyoka","NXDOMAIN","TXT record","Base32","base64.*\\."]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='DNS Tunneling Indicators' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Cobalt Strike Beacon Indicators',
  'Detects Cobalt Strike default malleable C2 profiles and beacon patterns.',
  'critical','Command and Control','T1071.001','Application Layer Protocol: Web Protocols',
  'proxy','','','stable',
  '["attack.command_and_control","attack.t1071.001"]','["Authorized red-team engagements"]',
  '["https://attack.mitre.org/techniques/T1071/001/"]',
  '["__cfduid=","bid=","__utmz=","Mozilla/5.0 (compatible; MSIE 9.0","pipe","msagent_","/jquery-3.3.1.slim.min.js","Beacon","beacon.dll"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Cobalt Strike Beacon Indicators' AND tenant_id=v_t);

-- ── EXFILTRATION ──────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Data Exfiltration via Cloud Storage',
  'Detects large uploads to cloud storage services that may indicate data exfiltration.',
  'high','Exfiltration','T1567.002','Exfiltration Over Web Service: Exfiltration to Cloud Storage',
  'proxy','','','stable',
  '["attack.exfiltration","attack.t1567.002"]','["Legitimate cloud backup operations","Authorized data migration"]',
  '["https://attack.mitre.org/techniques/T1567/002/"]',
  '["PUT.*amazonaws.com","PUT.*blob.core.windows.net","PUT.*storage.googleapis.com","PUT.*dropbox.com","rclone copy","rclone sync","aws s3 cp","gsutil cp"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Data Exfiltration via Cloud Storage' AND tenant_id=v_t);

-- ── IMPACT ────────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Ransomware File Extension Pattern',
  'Detects mass file rename or creation with known ransomware extension patterns.',
  'critical','Impact','T1486','Data Encrypted for Impact',
  'file_event','','','stable',
  '["attack.impact","attack.t1486"]','["Encryption tools used by legitimate backup software"]',
  '["https://attack.mitre.org/techniques/T1486/"]',
  '[".locked",".encrypted",".encrypt",".WNCRY",".WNCRYT",".locky",".cerber",".zepto",".crypto",".crypt",".crypz",".DEMON",".DECRYPT",".ryuk","HOW_TO_DECRYPT","RESTORE_FILES","YOUR_FILES","ransom"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Ransomware File Extension Pattern' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Shadow Copies Deleted',
  'Detects deletion of Volume Shadow Copies — a key ransomware pre-cursor step.',
  'critical','Impact','T1490','Inhibit System Recovery',
  'process_creation','windows','','stable',
  '["attack.impact","attack.t1490"]','["Legitimate disk management"]',
  '["https://attack.mitre.org/techniques/T1490/"]',
  '["vssadmin delete shadows","wmic shadowcopy delete","bcdedit /set {default} recoveryenabled no","bcdedit /set {default} bootstatuspolicy","vssadmin resize shadowstorage","wbadmin delete catalog","diskshadow delete shadows all"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Shadow Copies Deleted' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Mass File Deletion',
  'Detects bulk file deletion commands that may indicate data destruction or ransomware activity.',
  'high','Impact','T1485','Data Destruction',
  'process_creation','','','stable',
  '["attack.impact","attack.t1485"]','["Authorized bulk file cleanup by admin"]',
  '["https://attack.mitre.org/techniques/T1485/"]',
  '["rm -rf /","rm -rf /*","rm -rf /home","shred -u","find / -delete","del /s /q /f","format c: /y","cipher /w"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Mass File Deletion' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Disk or MBR Wipe',
  'Detects attempts to wipe disk sectors, MBR, or partition table to destroy system boot capability.',
  'critical','Impact','T1561','Disk Wipe',
  'process_creation','','','stable',
  '["attack.impact","attack.t1561"]','["Authorized disk imaging/decommission"]',
  '["https://attack.mitre.org/techniques/T1561/"]',
  '["dd if=/dev/zero of=/dev/sd","dd if=/dev/urandom of=/dev/sd","wipe -kq /dev/sd","shred /dev/sd","SDelete","diskpart clean","bootrec /fixmbr"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Disk or MBR Wipe' AND tenant_id=v_t);

-- ── BONUS: CLOUD / CONTAINER / SUPPLY CHAIN ──────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Kubernetes Privileged Container Launched',
  'Detects containers started with --privileged flag, providing full host access.',
  'high','Privilege Escalation','T1611','Escape to Host',
  'container','','','stable',
  '["attack.privilege_escalation","attack.t1611"]','["Authorized privileged containers for host monitoring"]',
  '["https://attack.mitre.org/techniques/T1611/"]',
  '["--privileged","privileged: true","securityContext: privileged","docker run --privileged","--cap-add SYS_ADMIN","--security-opt seccomp=unconfined"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Kubernetes Privileged Container Launched' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Supply Chain: curl-bash Pipe Execution',
  'Detects the classic supply chain attack pattern of piping a remote script directly into bash.',
  'high','Initial Access','T1195','Supply Chain Compromise',
  'process_creation','','','stable',
  '["attack.initial_access","attack.t1195"]','["Legitimate software installers (Homebrew, rustup, etc.) — verify URL before allowing"]',
  '["https://attack.mitre.org/techniques/T1195/"]',
  '["curl.*| bash","curl.*| sh","wget.*| bash","wget.*| sh","curl.*|bash","wget.*|bash","curl -s.*| sudo bash","fetch.*| bash"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Supply Chain: curl-bash Pipe Execution' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AWS CloudTrail: Root Account Login',
  'Detects login using the AWS root account — should be avoided per security best practices.',
  'high','Initial Access','T1078.004','Valid Accounts: Cloud Accounts',
  'cloud','','','stable',
  '["attack.initial_access","attack.t1078.004"]','["Emergency break-glass root access"]',
  '["https://attack.mitre.org/techniques/T1078/004/"]',
  '["ConsoleLogin","userIdentity.type: Root","\"type\":\"Root\"","eventName: ConsoleLogin","root account","arn:aws:iam::root"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AWS CloudTrail: Root Account Login' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'DCSync Attack Detected',
  'Detects DCSync — an attack that abuses replication to dump all domain password hashes.',
  'critical','Credential Access','T1003.006','OS Credential Dumping: DCSync',
  'process_creation','windows','','stable',
  '["attack.credential_access","attack.t1003.006"]','["Legitimate domain controller replication","Authorized AD backup"]',
  '["https://attack.mitre.org/techniques/T1003/006/"]',
  '["lsadump::dcsync","Invoke-DCSync","Get-ADReplAccount","EventID|exact:4662","DS-Replication-Get-Changes-All","replicatefrom","DRSGetNCChanges","drsuapi"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='DCSync Attack Detected' AND tenant_id=v_t);

END $$;
