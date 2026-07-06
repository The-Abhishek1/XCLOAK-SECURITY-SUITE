-- Migration 059: Sigma rule pack v2 — 51 additional curated rules.
-- Raises the total seeded rule count from 43 → 94.
-- Covers under-represented attack phases: LOLBins, persistence via WMI/BITS/
-- registry, cloud (AWS/Azure/GCP), container/K8s, C2 frameworks, and more.
--
-- All inserts use WHERE NOT EXISTS guards (idempotent on re-run).
-- tenant_id=1 is the default tenant created during initial setup.

DO $$
DECLARE v_t INT := 1;
BEGIN

-- ── EXECUTION — LOLBINS ───────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'CertUtil Used to Download or Decode File',
  'Detects certutil.exe abused as a downloader or base64 decoder — a common LOLBin technique.',
  'high','Defense Evasion','T1140','Deobfuscate/Decode Files or Information',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1140","attack.command_and_control","attack.t1105"]',
  '["Legitimate certificate management tasks using certutil"]',
  '["https://attack.mitre.org/techniques/T1140/"]',
  '["certutil -urlcache -split -f","certutil.exe -urlcache","certutil -decode","certutil.exe -decode","certutil -encode","certutil -decodehex","certutil /decode","certutil /urlcache"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='CertUtil Used to Download or Decode File' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Mshta Remote Content Execution',
  'Detects mshta.exe executing remote HTA content — a common LOLBin technique for payload delivery.',
  'high','Defense Evasion','T1218.005','System Binary Proxy Execution: Mshta',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1218.005"]','["Legitimate HTA applications used in enterprise"]',
  '["https://attack.mitre.org/techniques/T1218/005/"]',
  '["mshta http://","mshta.exe http://","mshta https://","mshta ftp://","mshta vbscript:","mshta javascript:","mshta.exe vbscript","mshta \\\\\\\\"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Mshta Remote Content Execution' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Regsvr32 COM Scriptlet Abuse',
  'Detects regsvr32 used to execute COM scriptlets (squiblydoo) for defense evasion.',
  'high','Defense Evasion','T1218.010','System Binary Proxy Execution: Regsvr32',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1218.010"]','["Legitimate DLL registration via regsvr32"]',
  '["https://attack.mitre.org/techniques/T1218/010/"]',
  '["regsvr32 /s /n /u /i:http","regsvr32.exe /s /u /i","regsvr32 scrobj.dll","regsvr32 /i:http://","regsvr32 /i:https://","regsvr32 /i:ftp://","regsvr32.exe /s scrobj"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Regsvr32 COM Scriptlet Abuse' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Odbcconf DLL Registration Abuse',
  'Detects odbcconf.exe used as a proxy to register and execute arbitrary DLLs.',
  'medium','Defense Evasion','T1218.008','System Binary Proxy Execution: Odbcconf',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1218.008"]','["Legitimate ODBC driver installation"]',
  '["https://attack.mitre.org/techniques/T1218/008/"]',
  '["odbcconf /a {regsvr","odbcconf.exe /a {REGSVR","odbcconf -a {regsvr","odbcconf /f","odbcconf.exe /s /a","ODBCCONF REGSVR"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Odbcconf DLL Registration Abuse' AND tenant_id=v_t);

-- ── PERSISTENCE ───────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Registry Run Key Persistence',
  'Detects modifications to registry Run and RunOnce keys used to establish persistence.',
  'medium','Persistence','T1547.001','Boot or Logon Autostart Execution: Registry Run Keys',
  'registry_event','windows','','stable',
  '["attack.persistence","attack.t1547.001"]','["Legitimate software installers","System administration tools"]',
  '["https://attack.mitre.org/techniques/T1547/001/"]',
  '["HKCU\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run","HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run","CurrentVersion\\\\RunOnce","CurrentVersion\\\\RunServices","reg add.*Run","New-ItemProperty.*Run","Set-ItemProperty.*Run"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Registry Run Key Persistence' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'WMI Event Subscription for Persistence',
  'Detects creation of WMI permanent event subscriptions — a stealthy persistence mechanism.',
  'high','Persistence','T1546.003','Event Triggered Execution: Windows Management Instrumentation Event Subscription',
  'process_creation','windows','','stable',
  '["attack.persistence","attack.t1546.003"]','["Legitimate monitoring tools using WMI event subscriptions"]',
  '["https://attack.mitre.org/techniques/T1546.003/"]',
  '["Register-WmiEvent","New-WMIEventSubscription","Set-WMIInstance -Class __EventFilter","mofcomp","__EventConsumer","CommandLineEventConsumer","ActiveScriptEventConsumer","__FilterToConsumerBinding"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='WMI Event Subscription for Persistence' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'BITS Job Used for Persistence or Download',
  'Detects Background Intelligent Transfer Service (BITS) jobs used to download payloads or persist.',
  'medium','Persistence','T1197','BITS Jobs',
  'process_creation','windows','','stable',
  '["attack.persistence","attack.t1197","attack.defense_evasion"]','["Legitimate Windows Update or software distribution using BITS"]',
  '["https://attack.mitre.org/techniques/T1197/"]',
  '["bitsadmin /addfile","bitsadmin /create","bitsadmin /SetNotifyCmdLine","bitsadmin /resume","bitsadmin /transfer","Start-BitsTransfer","BITSAdmin /Rawreturn","Add-BitsFile"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='BITS Job Used for Persistence or Download' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Browser Extension Installed from Unusual Path',
  'Detects browser extension installations from non-store paths, indicating potential persistence.',
  'medium','Persistence','T1176','Browser Extensions',
  'file_event','','','stable',
  '["attack.persistence","attack.t1176"]','["Developer mode extension loading during development"]',
  '["https://attack.mitre.org/techniques/T1176/"]',
  '["--load-extension=","--packed-extension=","Extensions\\\\Temp","AppData.*Extensions.*crx","AppData.*Extensions.*xpi","chrome-extension install","browser_action.crx"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Browser Extension Installed from Unusual Path' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'DLL Sideloading from User-Writable Path',
  'Detects DLLs loaded from user-writable directories by signed binaries — classic sideloading pattern.',
  'high','Persistence','T1574.002','Hijack Execution Flow: DLL Side-Loading',
  'process_creation','windows','','stable',
  '["attack.persistence","attack.defense_evasion","attack.t1574.002"]','["Legitimate software with DLLs in AppData (rare)"]',
  '["https://attack.mitre.org/techniques/T1574/002/"]',
  '["\\\\AppData\\\\Local\\\\Temp\\\\.*\\.dll","\\\\AppData\\\\Roaming\\\\.*\\.dll","\\\\Users\\\\Public\\\\.*\\.dll","\\\\ProgramData\\\\.*\\.dll","C:\\\\Temp\\\\.*\\.dll","%TEMP%\\\\.*\\.dll"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='DLL Sideloading from User-Writable Path' AND tenant_id=v_t);

-- ── DEFENSE EVASION ───────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AMSI Bypass Technique Detected',
  'Detects common AMSI (Antimalware Scan Interface) bypass methods used to avoid PS script scanning.',
  'high','Defense Evasion','T1562.001','Impair Defenses: Disable or Modify Tools',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1562.001"]','["Security research in controlled environments"]',
  '["https://attack.mitre.org/techniques/T1562/001/"]',
  '["amsiInitFailed","AmsiScanBuffer","amsi.dll","Reflection.Assembly","[Ref].Assembly.GetType","SetValue($null,0x1000)","[Runtime.InteropServices.Marshal]::Copy","Disable-AmsiProvider","amsi bypass"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AMSI Bypass Technique Detected' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'UAC Bypass via Fodhelper or Eventvwr',
  'Detects UAC bypass using fodhelper.exe or eventvwr.exe registry hijacking.',
  'high','Privilege Escalation','T1548.002','Abuse Elevation Control Mechanism: Bypass User Account Control',
  'process_creation','windows','','stable',
  '["attack.privilege_escalation","attack.t1548.002"]','["Legitimate Microsoft feature access"]',
  '["https://attack.mitre.org/techniques/T1548/002/"]',
  '["fodhelper.exe","eventvwr.exe","sdclt.exe /kickoffelev","HKCU:\\\\SOFTWARE\\\\Classes\\\\ms-settings","HKCU:\\\\SOFTWARE\\\\Classes\\\\mscfile","Bypass-UAC","Invoke-FodhelperBypass","UACMe"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='UAC Bypass via Fodhelper or Eventvwr' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Windows Firewall Disabled',
  'Detects commands that disable the Windows Firewall, which may indicate an attacker clearing defenses.',
  'high','Defense Evasion','T1562.004','Impair Defenses: Disable or Modify System Firewall',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.t1562.004"]','["Authorized firewall configuration changes by IT"]',
  '["https://attack.mitre.org/techniques/T1562/004/"]',
  '["netsh advfirewall set allprofiles state off","netsh firewall set opmode disable","Set-NetFirewallProfile -Enabled False","netsh advfirewall set currentprofile state off","sc stop mpssvc","reg add.*DisableFirewall"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Windows Firewall Disabled' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Timestomping — File Timestamp Manipulation',
  'Detects attempts to modify file timestamps to hide malicious activity timeline.',
  'medium','Defense Evasion','T1070.006','Indicator Removal: Timestomp',
  'process_creation','','','stable',
  '["attack.defense_evasion","attack.t1070.006"]','["System administrators modifying timestamps for legitimate reasons"]',
  '["https://attack.mitre.org/techniques/T1070/006/"]',
  '["touch -t 197001","touch --date=1970","$(Get-Date ''1970","[System.IO.File]::SetCreationTime","[System.IO.File]::SetLastWriteTime","timestomp","SetFileTime","metasploit timestomp"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Timestomping — File Timestamp Manipulation' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Process Hollowing or RunPE Indicators',
  'Detects memory manipulation API calls associated with process hollowing or RunPE injection.',
  'critical','Defense Evasion','T1055.012','Process Injection: Process Hollowing',
  'process_creation','windows','','stable',
  '["attack.defense_evasion","attack.privilege_escalation","attack.t1055.012"]','["Security tools performing legitimate process memory analysis"]',
  '["https://attack.mitre.org/techniques/T1055/012/"]',
  '["ZwUnmapViewOfSection","NtUnmapViewOfSection","WriteProcessMemory","CreateRemoteThread","VirtualAllocEx","SetThreadContext","NtSetContextThread","ResumeThread","RunPE","process hollowing"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Process Hollowing or RunPE Indicators' AND tenant_id=v_t);

-- ── CREDENTIAL ACCESS ─────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AWS Credentials File Accessed',
  'Detects access to AWS credential files on disk, which may indicate credential harvesting.',
  'high','Credential Access','T1552.001','Unsecured Credentials: Credentials In Files',
  'file_event','','','stable',
  '["attack.credential_access","attack.t1552.001"]','["Legitimate AWS CLI usage","Authorized automation scripts"]',
  '["https://attack.mitre.org/techniques/T1552/001/"]',
  '["cat ~/.aws/credentials","cat /root/.aws/credentials","type %USERPROFILE%\\.aws\\credentials",".aws/credentials",".aws/config","aws configure list","BOTO_CONFIG","AWS_SHARED_CREDENTIALS_FILE"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AWS Credentials File Accessed' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Cloud Instance Metadata SSRF',
  'Detects requests to cloud instance metadata service (IMDSv1) that may expose IAM credentials.',
  'critical','Credential Access','T1552.005','Unsecured Credentials: Cloud Instance Metadata API',
  'proxy','','','stable',
  '["attack.credential_access","attack.t1552.005"]','["Legitimate instance metadata access from application code"]',
  '["https://attack.mitre.org/techniques/T1552/005/"]',
  '["169.254.169.254","http://metadata.google.internal","http://169.254.169.254/latest/meta-data/iam","169.254.169.254/metadata/v1","http://metadata/computeMetadata","169.254.169.254/latest/user-data"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Cloud Instance Metadata SSRF' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AS-REP Roasting Attack',
  'Detects AS-REP Roasting — harvesting Kerberos AS-REP tickets from accounts without pre-auth.',
  'high','Credential Access','T1558.004','Steal or Forge Kerberos Tickets: AS-REP Roasting',
  'authentication','windows','','stable',
  '["attack.credential_access","attack.t1558.004"]','["Legitimate Kerberos authentication for accounts without pre-auth requirement"]',
  '["https://attack.mitre.org/techniques/T1558/004/"]',
  '["Invoke-ASREPRoast","Get-DomainUser -PreauthNotRequired","Rubeus asreproast","EventID|exact:4768","EncryptionType|exact:0x17","EncryptionType|exact:23","rc4_hmac_md5 AS-REQ","Get-ASREPHash"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AS-REP Roasting Attack' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Private Key or Credential File Accessed on Linux',
  'Detects access to private key files, .netrc, or bash history — sources of plaintext credentials.',
  'high','Credential Access','T1552.001','Unsecured Credentials: Credentials In Files',
  'file_event','linux','','stable',
  '["attack.credential_access","attack.t1552.001"]','["Developer accessing own SSH key","Legitimate key management"]',
  '["https://attack.mitre.org/techniques/T1552/001/"]',
  '["cat ~/.ssh/id_rsa","cat /root/.ssh/id_rsa","find / -name id_rsa","find / -name *.pem","cat /root/.bash_history","cat ~/.netrc","cat /etc/passwd","less /root/.netrc","type .netrc"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Private Key or Credential File Accessed on Linux' AND tenant_id=v_t);

-- ── DISCOVERY ─────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'System and Identity Discovery Commands',
  'Detects common system discovery commands run immediately post-exploitation.',
  'low','Discovery','T1033','System Owner/User Discovery',
  'process_creation','','','stable',
  '["attack.discovery","attack.t1033","attack.t1082"]','["Legitimate admin or monitoring scripts","User self-diagnosis"]',
  '["https://attack.mitre.org/techniques/T1033/"]',
  '["whoami /all","whoami /groups","whoami /priv","id; uname","uname -a; id","systeminfo | findstr","ipconfig /all","hostname; id","cat /proc/version","cat /etc/os-release","lscpu","dmidecode"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='System and Identity Discovery Commands' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Process and Network Connection Discovery',
  'Detects enumeration of running processes and network connections — typical post-exploitation recon.',
  'low','Discovery','T1057','Process Discovery',
  'process_creation','','','stable',
  '["attack.discovery","attack.t1057","attack.t1049"]','["Monitoring agents","Legitimate admin diagnostics"]',
  '["https://attack.mitre.org/techniques/T1057/"]',
  '["ps aux","ps -ef","tasklist /svc","tasklist /v","netstat -antp","netstat -tulnp","ss -tulnp","arp -a","route print","Get-Process","Get-NetTCPConnection","net sessions"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Process and Network Connection Discovery' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'File and Directory Discovery via Find or Dir',
  'Detects broad file system enumeration used to locate sensitive files post-compromise.',
  'low','Discovery','T1083','File and Directory Discovery',
  'process_creation','','','stable',
  '["attack.discovery","attack.t1083"]','["Legitimate file searches by administrators","Backup or indexing software"]',
  '["https://attack.mitre.org/techniques/T1083/"]',
  '["find / -name *.conf","find / -name *.env","find / -name passwords","find / -name *.key","find / -name *.pem","dir /s /b C:\\\\","Get-ChildItem -Recurse","find / -perm -4000","find /home -name .bash_history"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='File and Directory Discovery via Find or Dir' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Cloud Environment Discovery',
  'Detects enumeration of cloud resources, instance metadata, and IAM roles.',
  'medium','Discovery','T1580','Cloud Infrastructure Discovery',
  'process_creation','','','stable',
  '["attack.discovery","attack.t1580"]','["Authorized cloud administrators running inventory checks"]',
  '["https://attack.mitre.org/techniques/T1580/"]',
  '["aws ec2 describe-instances","aws iam list-users","aws s3 ls","gcloud compute instances list","gcloud iam list","az vm list","az ad user list","kubectl get nodes","kubectl get pods -A","az account list"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Cloud Environment Discovery' AND tenant_id=v_t);

-- ── LATERAL MOVEMENT ──────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'WMI Remote Lateral Movement',
  'Detects WMI used to invoke processes on remote systems — common lateral movement pattern.',
  'high','Lateral Movement','T1021.006','Remote Services: Windows Remote Management',
  'process_creation','windows','','stable',
  '["attack.lateral_movement","attack.t1021.006","attack.t1047"]','["Legitimate remote administration via WMI"]',
  '["https://attack.mitre.org/techniques/T1021/006/"]',
  '["wmic /node:.* process call create","Invoke-WmiMethod -ComputerName","Get-WmiObject -ComputerName","wmic /node:.* /user:","Invoke-CimMethod -ComputerName","New-CimSession -ComputerName","wmic /failfast:on /node"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='WMI Remote Lateral Movement' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Remote Desktop Session Hijacking via tscon',
  'Detects RDP session hijacking using tscon.exe to switch to another user''s session.',
  'high','Lateral Movement','T1563.002','Remote Service Session Hijacking: RDP Hijacking',
  'process_creation','windows','','stable',
  '["attack.lateral_movement","attack.t1563.002"]','["Legitimate session switching by administrators"]',
  '["https://attack.mitre.org/techniques/T1563/002/"]',
  '["tscon.exe","tscon /dest:console","cmd /k tscon","tscon 1 /dest","createservice.*tscon","sc create.*tscon","SYSTEM.*tscon"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Remote Desktop Session Hijacking via tscon' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'DCOM Lateral Movement',
  'Detects DCOM-based lateral movement using MMC20, ShellWindows, or ShellBrowserWindow objects.',
  'high','Lateral Movement','T1021.003','Remote Services: Distributed Component Object Model',
  'process_creation','windows','','stable',
  '["attack.lateral_movement","attack.t1021.003"]','["Legitimate COM-based remote administration"]',
  '["https://attack.mitre.org/techniques/T1021/003/"]',
  '["MMC20.Application","ShellWindows","ShellBrowserWindow","[activator]::CreateInstance","[type]::GetTypeFromProgID","GetObject.*winmgmts","Invoke-DCOM","dcomcnfg","mmc /nodefile"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='DCOM Lateral Movement' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'SSH ProxyJump or ProxyCommand Lateral Movement',
  'Detects SSH with ProxyJump or ProxyCommand options used for tunneling to internal hosts.',
  'medium','Lateral Movement','T1021.004','Remote Services: SSH',
  'process_creation','linux','','stable',
  '["attack.lateral_movement","attack.t1021.004"]','["Legitimate bastion host SSH configurations","Jump server setups"]',
  '["https://attack.mitre.org/techniques/T1021/004/"]',
  '["ssh -J ","ssh -o ProxyJump","ssh -o ProxyCommand","ssh -ProxyCommand","ProxyCommand=","StrictHostKeyChecking=no -o ProxyCommand","ssh -W %h:%p","ssh.*-i.*@.*@"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='SSH ProxyJump or ProxyCommand Lateral Movement' AND tenant_id=v_t);

-- ── COLLECTION ────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Clipboard Data Access',
  'Detects tools and commands used to read clipboard contents — may capture passwords or sensitive data.',
  'medium','Collection','T1115','Clipboard Data',
  'process_creation','','','stable',
  '["attack.collection","attack.t1115"]','["Legitimate clipboard managers","Password managers reading clipboard"]',
  '["https://attack.mitre.org/techniques/T1115/"]',
  '["Get-Clipboard","xclip -o","xclip -selection clipboard","xdotool getclipboard","pbpaste","clip.exe","win32clipboard","OpenClipboard","GetClipboardData"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Clipboard Data Access' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Screenshot Capture Tool Executed',
  'Detects execution of screenshot capture tools which may be used for data collection.',
  'medium','Collection','T1113','Screen Capture',
  'process_creation','','','stable',
  '["attack.collection","attack.t1113"]','["Legitimate remote support tools","Monitoring software","User screen capture for bug reports"]',
  '["https://attack.mitre.org/techniques/T1113/"]',
  '["scrot ","gnome-screenshot","screencapture -x","nircmd.exe savescreenshot","xwd -root","import -window root","ScreenCapture","Invoke-Screenshot","screenshot.exe","[System.Windows.Forms.Screen]"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Screenshot Capture Tool Executed' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Email Archive or PST File Accessed',
  'Detects access to Outlook PST/OST archive files which may contain sensitive email content.',
  'high','Collection','T1114.001','Email Collection: Local Email Collection',
  'file_event','windows','','stable',
  '["attack.collection","attack.t1114.001"]','["Legitimate email client opening user mailbox"]',
  '["https://attack.mitre.org/techniques/T1114/001/"]',
  '["*.pst","*.ost","outlook.exe","\\\\AppData.*Outlook","MAPI","MapiMail","Copy-Item.*\\.pst","Compress-Archive.*\\.pst","robocopy.*\\.pst","xcopy.*\\.pst"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Email Archive or PST File Accessed' AND tenant_id=v_t);

-- ── COMMAND AND CONTROL ───────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Ngrok Tunnel Detected',
  'Detects ngrok tunneling tool execution — often used by attackers to expose internal services.',
  'high','Command and Control','T1572','Protocol Tunneling',
  'process_creation','','','stable',
  '["attack.command_and_control","attack.t1572"]','["Legitimate developer use for webhook testing","Authorized remote access tunneling"]',
  '["https://attack.mitre.org/techniques/T1572/"]',
  '["ngrok http","ngrok tcp","ngrok tls","ngrok.exe http","ngrok.io","ngrok authtoken","./ngrok ","ngrok start","ngrok tunnel"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Ngrok Tunnel Detected' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Chisel Proxy Tunnel Tool',
  'Detects Chisel — a fast TCP/UDP tunnel over HTTP used for C2 and firewall bypass.',
  'high','Command and Control','T1090.003','Proxy: Multi-hop Proxy',
  'process_creation','','','stable',
  '["attack.command_and_control","attack.t1090.003"]','["Authorized penetration testers using Chisel for tunneling"]',
  '["https://attack.mitre.org/techniques/T1090/003/"]',
  '["chisel server","chisel client","chisel_linux","chisel_windows","chisel.exe","./chisel ","chisel --reverse","chisel -p ","chisel socks"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Chisel Proxy Tunnel Tool' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Sliver or Havoc C2 Framework Indicators',
  'Detects Sliver and Havoc C2 frameworks used in offensive operations.',
  'critical','Command and Control','T1071.001','Application Layer Protocol: Web Protocols',
  'process_creation','','','stable',
  '["attack.command_and_control","attack.t1071.001"]','["Authorized red-team engagements with documented scope"]',
  '["https://attack.mitre.org/techniques/T1071/001/"]',
  '["sliver-server","sliver-client","sliver-implant","havoc teamserver","havoc.exe","HavocUI","Havoc C2","teamserver.py","./teamserver ","sliver generate","sliver armory"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Sliver or Havoc C2 Framework Indicators' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'TOR Browser or Anonymous Proxy Usage',
  'Detects TOR browser execution or known TOR proxy configuration on an endpoint.',
  'high','Command and Control','T1090.003','Proxy: Multi-hop Proxy',
  'process_creation','','','stable',
  '["attack.command_and_control","attack.t1090.003"]','["Legitimate privacy-conscious users","Authorized security research"]',
  '["https://attack.mitre.org/techniques/T1090/003/"]',
  '["tor.exe","torbrowser","tor browser","Tor Browser","torbrowser-install","9050","9150","SOCKS.*127.0.0.1.*9050","onion","torrc","tor -f torrc"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='TOR Browser or Anonymous Proxy Usage' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Metasploit Framework Indicators',
  'Detects Metasploit msfconsole, msfvenom, and payload staging patterns.',
  'critical','Command and Control','T1587.001','Develop Capabilities: Malware',
  'process_creation','','','stable',
  '["attack.command_and_control","attack.t1587.001"]','["Authorized penetration testing engagements"]',
  '["https://attack.mitre.org/techniques/T1587/001/"]',
  '["msfconsole","msfvenom","msfpayload","msf>","msf5>","msf6>","metasploit","multi/handler","payload/linux","payload/windows","reverse_tcp","reverse_https","meterpreter"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Metasploit Framework Indicators' AND tenant_id=v_t);

-- ── EXFILTRATION ──────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'FTP or SCP Data Exfiltration',
  'Detects file transfer via FTP, SCP, or SFTP to external hosts that may indicate exfiltration.',
  'high','Exfiltration','T1048','Exfiltration Over Alternative Protocol',
  'process_creation','','','stable',
  '["attack.exfiltration","attack.t1048"]','["Authorized file transfers to external partners","Backup operations"]',
  '["https://attack.mitre.org/techniques/T1048/"]',
  '["ftp -n -s:","sftp -b","scp -r","ncftp -u","lftp -c","wput","ncftpput","ftp-upload","scp.*@.*:/","sftp.*@.*","put.*ftp://","ftps://"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='FTP or SCP Data Exfiltration' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Rclone or Megatools Cloud Exfiltration',
  'Detects rclone and megatools used to sync or upload data to cloud storage for exfiltration.',
  'high','Exfiltration','T1567.002','Exfiltration Over Web Service: Exfiltration to Cloud Storage',
  'process_creation','','','stable',
  '["attack.exfiltration","attack.t1567.002"]','["Authorized cloud backup operations using rclone"]',
  '["https://attack.mitre.org/techniques/T1567.002/"]',
  '["rclone copy","rclone sync","rclone move","rclone --config","megacopy","megatools put","megadl","megaput","megatools sync","mega-copy","mega-put"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Rclone or Megatools Cloud Exfiltration' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'ICMP Tunneling for Data Exfiltration',
  'Detects ICMP-based tunneling tools used to exfiltrate data through firewall-permitted ICMP.',
  'high','Exfiltration','T1048.001','Exfiltration Over Symmetric Encrypted Non-C2 Protocol',
  'process_creation','','','stable',
  '["attack.exfiltration","attack.command_and_control","attack.t1048.001"]','["Network diagnostic tools using large ICMP packets"]',
  '["https://attack.mitre.org/techniques/T1048/001/"]',
  '["icmptunnel","ptunnel","ptunnel-ng","ping -s 65000","ping -l 65000","icmp exfil","nping --icmp","icmpsh","icmp-shell","icmpexfil"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='ICMP Tunneling for Data Exfiltration' AND tenant_id=v_t);

-- ── CLOUD ─────────────────────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AWS CloudTrail Logging Disabled or Deleted',
  'Detects deletion or disabling of CloudTrail trails — a key attacker step before destructive activity.',
  'critical','Defense Evasion','T1562.008','Impair Defenses: Disable Cloud Logs',
  'cloud','','','stable',
  '["attack.defense_evasion","attack.t1562.008"]','["Authorized CloudTrail configuration changes during compliance review"]',
  '["https://attack.mitre.org/techniques/T1562/008/"]',
  '["aws cloudtrail delete-trail","aws cloudtrail stop-logging","cloudtrail:DeleteTrail","cloudtrail:StopLogging","DeleteTrail","StopLogging","aws cloudtrail put-event-selectors --no-include-management-events"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AWS CloudTrail Logging Disabled or Deleted' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AWS S3 Bucket Made Public',
  'Detects S3 bucket ACL or policy changes that make bucket contents publicly readable.',
  'critical','Exfiltration','T1530','Data from Cloud Storage',
  'cloud','','','stable',
  '["attack.exfiltration","attack.t1530"]','["Intentional public bucket for static website hosting"]',
  '["https://attack.mitre.org/techniques/T1530/"]',
  '["aws s3api put-bucket-acl --acl public-read","put-bucket-policy.*Principal.*\\*","s3:GetObject.*Allow.*\\*","PutBucketAcl","PutBucketPolicy","public-read-write","aws s3 website"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AWS S3 Bucket Made Public' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'AWS IAM Privilege Escalation',
  'Detects IAM privilege escalation techniques including policy attachment and account creation.',
  'critical','Privilege Escalation','T1078.004','Valid Accounts: Cloud Accounts',
  'cloud','','','stable',
  '["attack.privilege_escalation","attack.t1078.004"]','["Authorized IAM administration","Cloud security reviews"]',
  '["https://attack.mitre.org/techniques/T1078/004/"]',
  '["iam:AttachUserPolicy.*AdministratorAccess","iam:CreateLoginProfile","iam:UpdateLoginProfile","iam:CreateAccessKey","iam:PassRole","iam:PutRolePolicy","aws iam create-user","AttachUserPolicy","CreateLoginProfile"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='AWS IAM Privilege Escalation' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Azure Service Principal Credential Reset',
  'Detects Azure SP credential reset or addition — attackers use this to maintain persistent cloud access.',
  'high','Persistence','T1098.001','Account Manipulation: Additional Cloud Credentials',
  'cloud','','','stable',
  '["attack.persistence","attack.t1098.001"]','["Authorized SP rotation by cloud administrators"]',
  '["https://attack.mitre.org/techniques/T1098/001/"]',
  '["az ad sp credential reset","New-AzADServicePrincipalCredential","az ad sp credential list","Add-AzADServicePrincipalCredential","Update-AzADApplication","Microsoft.KeyVault/vaults/accessPolicies/write"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Azure Service Principal Credential Reset' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'GCP Service Account Key Exported',
  'Detects creation or download of GCP service account keys — high-value for long-term cloud access.',
  'high','Credential Access','T1552.001','Unsecured Credentials: Credentials In Files',
  'cloud','','','stable',
  '["attack.credential_access","attack.t1552.001"]','["Authorized GCP service account key rotation"]',
  '["https://attack.mitre.org/techniques/T1552/001/"]',
  '["gcloud iam service-accounts keys create","serviceaccounts.keys.create","CreateServiceAccountKey","iam.serviceAccountKeys.create","gcloud iam service-accounts keys list","Export-GcpServiceAccountKey"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='GCP Service Account Key Exported' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Cloud Compute Instance Created in New Region',
  'Detects cloud VM creation outside of expected regions — may indicate cryptomining or data staging.',
  'medium','Impact','T1578.002','Modify Cloud Compute Infrastructure: Create Cloud Instance',
  'cloud','','','stable',
  '["attack.impact","attack.t1578.002"]','["Authorized expansion to new cloud regions","Disaster recovery testing"]',
  '["https://attack.mitre.org/techniques/T1578/002/"]',
  '["aws ec2 run-instances","gcloud compute instances create","az vm create","CreateInstance","RunInstances","DescribeInstances","ec2:RunInstances","compute.instances.insert"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Cloud Compute Instance Created in New Region' AND tenant_id=v_t);

-- ── CONTAINER / KUBERNETES ────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Docker Socket Accessed from Container',
  'Detects access to the Docker daemon socket from within a container — enables container escape.',
  'critical','Privilege Escalation','T1611','Escape to Host',
  'container','','','stable',
  '["attack.privilege_escalation","attack.t1611"]','["Authorized Docker-in-Docker (DinD) setups","CI/CD runners requiring Docker access"]',
  '["https://attack.mitre.org/techniques/T1611/"]',
  '["/var/run/docker.sock","DOCKER_HOST=unix:///var/run/docker.sock","docker -H unix:///var/run/docker.sock","docker.sock","mount.*docker.sock","volume.*docker.sock","sock:/var/run/docker"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Docker Socket Accessed from Container' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Kubectl Exec Into Running Pod',
  'Detects kubectl exec used to gain interactive shell access to a running pod.',
  'high','Execution','T1609','Container Administration Command',
  'process_creation','','','stable',
  '["attack.execution","attack.t1609"]','["Authorized developer debugging sessions","SRE incident response"]',
  '["https://attack.mitre.org/techniques/T1609/"]',
  '["kubectl exec -it","kubectl exec --stdin","kubectl exec -n.*-- /bin/sh","kubectl exec -n.*-- /bin/bash","kubectl exec pod","kubectl exec -c ","kubectl attach"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Kubectl Exec Into Running Pod' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Kubernetes ClusterRoleBinding to cluster-admin',
  'Detects creation of ClusterRoleBindings to cluster-admin role — grants full cluster access.',
  'critical','Privilege Escalation','T1098','Account Manipulation',
  'process_creation','','','stable',
  '["attack.privilege_escalation","attack.t1098"]','["Authorized cluster setup by platform team"]',
  '["https://attack.mitre.org/techniques/T1098/"]',
  '["kubectl create clusterrolebinding","roleRef: name: cluster-admin","clusterrole: cluster-admin","clusterRoleBinding.*cluster-admin","rbac.authorization.k8s.io/v1.*ClusterRoleBinding","kind: ClusterRoleBinding"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Kubernetes ClusterRoleBinding to cluster-admin' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Kubernetes Secrets Enumeration',
  'Detects mass enumeration of Kubernetes secrets, which may contain credentials and API keys.',
  'high','Credential Access','T1552.007','Unsecured Credentials: Container API',
  'process_creation','','','stable',
  '["attack.credential_access","attack.t1552.007"]','["Authorized platform operators running cluster audits"]',
  '["https://attack.mitre.org/techniques/T1552/007/"]',
  '["kubectl get secrets -A","kubectl get secrets --all-namespaces","kubectl get secret -n","kubectl describe secret","kubectl get secrets -o yaml","kubectl get secret.*-o json","kube-hunter","kubeletctl secrets"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Kubernetes Secrets Enumeration' AND tenant_id=v_t);

-- ── SUPPLY CHAIN / RECONNAISSANCE ────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'DNS Zone Transfer Attempt',
  'Detects DNS zone transfer (AXFR) requests used to enumerate all DNS records of a domain.',
  'medium','Reconnaissance','T1590.002','Gather Victim Network Information: DNS',
  'dns','','','stable',
  '["attack.reconnaissance","attack.t1590.002"]','["Authorized DNS audit","Secondary nameserver zone sync"]',
  '["https://attack.mitre.org/techniques/T1590/002/"]',
  '["dig axfr","dig AXFR","host -l ","nslookup -type=any","nslookup -query=ANY","fierce --domain","dnsrecon -t axfr","dnswalk","zone transfer","type=axfr"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='DNS Zone Transfer Attempt' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Malicious npm or pip Package Install Pattern',
  'Detects npm/pip installations of known typosquatted or suspicious package names.',
  'high','Initial Access','T1195.001','Supply Chain Compromise: Compromise Software Dependencies',
  'process_creation','','','stable',
  '["attack.initial_access","attack.t1195.001"]','["Legitimate package installation — verify package name spelling before allowlisting"]',
  '["https://attack.mitre.org/techniques/T1195/001/"]',
  '["npm install coIors","npm install crossenv","npm install node-uuid ","pip install requets","pip install setup-tools","pip install python-dateutil ","pip install urllib","npm install --save malicious","npx --yes "]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Malicious npm or pip Package Install Pattern' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'npm postinstall Script Downloading Remote Content',
  'Detects npm lifecycle scripts (postinstall) fetching and executing remote content.',
  'high','Execution','T1059.004','Command and Scripting Interpreter: Unix Shell',
  'process_creation','','','stable',
  '["attack.execution","attack.t1059.004","attack.initial_access","attack.t1195.001"]','["Legitimate npm packages with postinstall platform binary downloads"]',
  '["https://attack.mitre.org/techniques/T1059/004/"]',
  '["npm postinstall","node_modules/.bin","postinstall.*curl","postinstall.*wget","postinstall.*fetch","node install.js","node postinstall.js","npx --postinstall","scripts.postinstall"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='npm postinstall Script Downloading Remote Content' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Dependency Confusion Attack Pattern',
  'Detects internal package names being installed from public registries — dependency confusion attack.',
  'high','Initial Access','T1195.001','Supply Chain Compromise: Compromise Software Dependencies',
  'process_creation','','','stable',
  '["attack.initial_access","attack.t1195.001"]','["Developers explicitly installing a public package with an internal name (document the exception)"]',
  '["https://attack.mitre.org/techniques/T1195/001/"]',
  '["pip install.*--index-url.*pypi.org","npm install.*--registry.*npmjs.com.*internal","npm config set registry.*npmjs","pip config set.*index-url.*pypi","pip install.*--extra-index-url","npm publish.*internal"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Dependency Confusion Attack Pattern' AND tenant_id=v_t);

-- ── IMPACT — ADDITIONAL ───────────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Cryptocurrency Mining Indicators',
  'Detects cryptomining tools and connection patterns indicating unauthorized resource use.',
  'high','Impact','T1496','Resource Hijacking',
  'process_creation','','','stable',
  '["attack.impact","attack.t1496"]','["Authorized cryptocurrency-related work on dedicated machines"]',
  '["https://attack.mitre.org/techniques/T1496/"]',
  '["xmrig","xmrig-cuda","xmrig-opencl","minerd","cpuminer","ethminer","t-rex miner","stratum+tcp://","pool.supportxmr.com","moneroocean.stream","--donate-level 0","mining pool"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Cryptocurrency Mining Indicators' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Container or VM Escape via OverlayFS',
  'Detects exploitation of overlayfs or cgroups vulnerabilities for container escape.',
  'critical','Privilege Escalation','T1611','Escape to Host',
  'process_creation','linux','','stable',
  '["attack.privilege_escalation","attack.t1611"]','["Authorized kernel testing in isolated environments"]',
  '["https://attack.mitre.org/techniques/T1611/"]',
  '["CVE-2021-3493","CVE-2021-4034","CVE-2022-0847","overlayfs","dirty pipe","runc exec","nsenter --mount=/proc","unshare --user","unshare --map-root-user","cve-2022-0847"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Container or VM Escape via OverlayFS' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'SQL Injection Pattern in Web Logs',
  'Detects common SQL injection attack patterns in HTTP request URIs and parameters.',
  'high','Initial Access','T1190','Exploit Public-Facing Application',
  'webserver','','','stable',
  '["attack.initial_access","attack.t1190"]','["Security scanners","WAF test traffic","Authorized pen-test"]',
  '["https://attack.mitre.org/techniques/T1190/"]',
  '[" OR 1=1","'' OR 1=1","UNION SELECT","UNION ALL SELECT","1'' OR ''1''=''1","admin''--","; DROP TABLE","1;DROP","SLEEP(5)","BENCHMARK(","WAITFOR DELAY","INTO OUTFILE","LOAD_FILE(","information_schema"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='SQL Injection Pattern in Web Logs' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Cross-Site Scripting (XSS) Attempt in Web Logs',
  'Detects reflected XSS patterns in web request parameters from web server logs.',
  'medium','Initial Access','T1190','Exploit Public-Facing Application',
  'webserver','','','stable',
  '["attack.initial_access","attack.t1190"]','["Security scanners","WAF test traffic","Authorized pen-test"]',
  '["https://attack.mitre.org/techniques/T1190/"]',
  '["<script>alert","<script>document.cookie","javascript:alert","onerror=alert","onload=alert","<img src=x onerror","<svg onload","<iframe src=javascript","onfocus=alert","document.write(","XMLHttpRequest","fetch(''http"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Cross-Site Scripting (XSS) Attempt in Web Logs' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Path Traversal Attack Detected',
  'Detects directory traversal patterns in HTTP requests attempting to read sensitive server files.',
  'high','Initial Access','T1190','Exploit Public-Facing Application',
  'webserver','','','stable',
  '["attack.initial_access","attack.t1190"]','["Security scanners","WAF test traffic","Authorized pen-test"]',
  '["https://attack.mitre.org/techniques/T1190/"]',
  '["../../../etc/passwd","..%2F..%2F..%2Fetc","..\\\\..\\\\..\\\\windows\\\\","..%5C..%5C","....//....//","..%252f..%252f","..%c0%af..%c0%af","/etc/shadow","WEB-INF/web.xml","..%00/","boot.ini"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Path Traversal Attack Detected' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Server-Side Request Forgery (SSRF) Attempt',
  'Detects SSRF patterns targeting internal services or cloud metadata endpoints via web parameters.',
  'high','Initial Access','T1190','Exploit Public-Facing Application',
  'webserver','','','stable',
  '["attack.initial_access","attack.t1190"]','["Authorized penetration tests","Security scanner traffic"]',
  '["https://attack.mitre.org/techniques/T1190/"]',
  '["169.254.169.254","http://localhost/","http://127.0.0.1/","http://[::1]/","http://0.0.0.0/","file:///etc/passwd","dict://","gopher://","http://internal.","url=http://10.","url=file://","url=http://192.168"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Server-Side Request Forgery (SSRF) Attempt' AND tenant_id=v_t);

-- ── ADDITIONAL INITIAL ACCESS ──────────────────────────────────────────────────

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Phishing Email Attachment Opened',
  'Detects execution of Office documents or script files from common email attachment delivery paths.',
  'high','Initial Access','T1566.001','Phishing: Spearphishing Attachment',
  'process_creation','windows','','stable',
  '["attack.initial_access","attack.t1566.001"]','["Legitimate document opened from email downloads folder"]',
  '["https://attack.mitre.org/techniques/T1566/001/"]',
  '["winword.exe.*Downloads","excel.exe.*Downloads","powerpnt.exe.*Downloads","wscript.exe.*Temp","cscript.exe.*Temp","mshta.exe.*Downloads","winword.*\\\\AppData.*Temp","WINWORD.*Roaming","cmd.exe.*winword"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Phishing Email Attachment Opened' AND tenant_id=v_t);

INSERT INTO sigma_rules
  (title,description,severity,mitre_tactic,mitre_technique,mitre_name,
   logsource_cat,logsource_prod,logsource_svc,status,
   tags,falsepositives,"references",keywords,selections,condition,enabled,tenant_id)
SELECT
  'Suspicious Office Macro Execution',
  'Detects Office macro activity spawning shells or scripting engines — common malware delivery vector.',
  'high','Execution','T1204.002','User Execution: Malicious File',
  'process_creation','windows','','stable',
  '["attack.execution","attack.t1204.002","attack.initial_access","attack.t1566"]','["Legitimate Office VBA macros for automation"]',
  '["https://attack.mitre.org/techniques/T1204/002/"]',
  '["WINWORD.EXE.*cmd.exe","EXCEL.EXE.*cmd.exe","POWERPNT.EXE.*cmd.exe","winword.*powershell","excel.*wscript","winword.*mshta","WINWORD.*bitsadmin","excel.*cscript","OUTLOOK.*powershell","outlook.*cmd.exe"]',
  '{}'::jsonb,'',true,v_t
WHERE NOT EXISTS (SELECT 1 FROM sigma_rules WHERE title='Suspicious Office Macro Execution' AND tenant_id=v_t);

END $$;
