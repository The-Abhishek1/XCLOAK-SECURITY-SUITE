import 'dart:convert';
import 'package:http/http.dart' as http;
import '../services/api_client.dart';
import '../services/secure_storage.dart';

class AdminUnauthorizedException implements Exception {
  final String message;
  const AdminUnauthorizedException(this.message);
  @override String toString() => message;
}

class DashboardApi {
  /// Legacy: create from stored API key (backward compat).
  static Future<DashboardApi?> create() async {
    final url    = await SecureStore.serverUrl();
    final apiKey = await SecureStore.apiKey();
    if (url == null || url.isEmpty || apiKey == null || apiKey.isEmpty) return null;
    return DashboardApi._(ApiClient(baseUrl: url, agentToken: apiKey));
  }

  /// Login with email + password. Verifies admin role. Saves session cookie.
  /// Throws [AdminUnauthorizedException] if credentials are valid but role insufficient.
  /// Throws [ApiException] / [Exception] on network/server error.
  static Future<DashboardApi> login(String serverUrl, String email, String password) async {
    // 1 — Authenticate
    final loginRes = await http.post(
      Uri.parse('$serverUrl/api/auth/login'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'email': email, 'password': password}),
    ).timeout(const Duration(seconds: 15));

    if (loginRes.statusCode == 401 || loginRes.statusCode == 403) {
      throw const AdminUnauthorizedException('Invalid credentials');
    }
    if (loginRes.statusCode < 200 || loginRes.statusCode >= 300) {
      throw ApiException(loginRes.statusCode, 'Login failed (${loginRes.statusCode})');
    }

    // 2 — Extract token from JSON body (backend returns it for Dart/mobile clients)
    //     Fall back to parsing Set-Cookie header if the field is absent.
    String rawToken = '';
    try {
      final json = jsonDecode(loginRes.body) as Map<String, dynamic>;
      rawToken = (json['token'] ?? '').toString();
    } catch (_) {}

    if (rawToken.isEmpty) {
      final setCookie = loginRes.headers['set-cookie'] ?? '';
      final m = RegExp(r'(?:^|[\s,])token=([^;,\s]+)').firstMatch(setCookie);
      rawToken = m?.group(1) ?? '';
    }

    if (rawToken.isEmpty) {
      throw Exception(
        'Server did not return an auth token.\n'
        'Verify the server URL is reachable: $serverUrl',
      );
    }
    final cookie = 'token=$rawToken';

    // 3 — Fetch user profile & verify admin role
    final meRes = await http.get(
      Uri.parse('$serverUrl/api/auth/profile'),
      headers: {'Cookie': cookie},
    ).timeout(const Duration(seconds: 10));

    if (meRes.statusCode != 200) {
      throw ApiException(meRes.statusCode, 'Could not verify account');
    }

    final profile = jsonDecode(meRes.body) as Map<String, dynamic>;
    final isPlatformAdmin = profile['is_platform_admin'] == true;
    final role = (profile['role'] ?? '').toString().toLowerCase();
    final isAdmin = isPlatformAdmin || role == 'admin' || role == 'platform_admin';

    if (!isAdmin) {
      throw const AdminUnauthorizedException(
          'Access denied — admin or platform_admin role required');
    }

    // 4 — Persist session
    final displayEmail = (profile['email'] ?? email).toString();
    await SecureStore.saveAdminSession(
      cookie: cookie,
      email: displayEmail,
      role: isPlatformAdmin ? 'Platform Admin' : 'Admin',
    );

    return DashboardApi._(ApiClient(baseUrl: serverUrl, cookie: cookie));
  }

  /// Login with an API key (xck_...). Verifies admin role via /api/auth/profile.
  static Future<DashboardApi> loginWithApiKey(String serverUrl, String apiKey) async {
    final trimmed = apiKey.trim();
    if (!trimmed.startsWith('xck_')) {
      throw const AdminUnauthorizedException('API key must start with xck_');
    }
    final profileRes = await http.get(
      Uri.parse('$serverUrl/api/auth/profile'),
      headers: {'Authorization': 'Bearer $trimmed'},
    ).timeout(const Duration(seconds: 10));

    if (profileRes.statusCode == 401 || profileRes.statusCode == 403) {
      throw const AdminUnauthorizedException('Invalid API key');
    }
    if (profileRes.statusCode != 200) {
      throw ApiException(profileRes.statusCode, 'Could not verify API key (${profileRes.statusCode})');
    }

    final profile = jsonDecode(profileRes.body) as Map<String, dynamic>;
    final role = (profile['role'] ?? '').toString().toLowerCase();
    final isPlatformAdmin = profile['is_platform_admin'] == true;
    final isAdmin = isPlatformAdmin || role == 'admin' || role == 'platform_admin';
    if (!isAdmin) {
      throw const AdminUnauthorizedException('API key does not have admin privileges');
    }

    await SecureStore.saveAdminSession(
      cookie: '',
      email: (profile['email'] ?? 'api-key').toString(),
      role: isPlatformAdmin ? 'Platform Admin' : 'Admin',
    );
    await SecureStore.saveApiKey(trimmed);

    return DashboardApi._(ApiClient(baseUrl: serverUrl, agentToken: trimmed));
  }

  /// Restore admin session from stored cookie or API key. Returns null if none / expired.
  static Future<DashboardApi?> createFromSession() async {
    final url = await SecureStore.serverUrl();
    if (url == null || url.isEmpty) return null;

    final cookie = await SecureStore.adminCookie() ?? '';
    final apiKey = await SecureStore.apiKey() ?? '';

    // Prefer cookie session; fall back to stored API key.
    final Map<String, String> headers = {};
    ApiClient? client;

    if (cookie.isNotEmpty) {
      headers['Cookie'] = cookie;
      client = ApiClient(baseUrl: url, cookie: cookie);
    } else if (apiKey.startsWith('xck_')) {
      headers['Authorization'] = 'Bearer $apiKey';
      client = ApiClient(baseUrl: url, agentToken: apiKey);
    } else {
      return null;
    }

    try {
      final meRes = await http.get(
        Uri.parse('$url/api/auth/profile'),
        headers: headers,
      ).timeout(const Duration(seconds: 8));

      if (meRes.statusCode != 200) {
        await SecureStore.clearAdminSession();
        return null;
      }
      final profile = jsonDecode(meRes.body) as Map<String, dynamic>;
      final isAdmin = profile['is_platform_admin'] == true ||
          (profile['role'] ?? '').toString().toLowerCase() == 'admin';
      if (!isAdmin) { await SecureStore.clearAdminSession(); return null; }

      return DashboardApi._(client!);
    } catch (_) {
      return null;
    }
  }
  DashboardApi._(this.c);
  final ApiClient c;

  // ── helpers ───────────────────────────────────────────────────────────────
  Future<Map<String,dynamic>> _g(String p) async => (await c.get(p)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _po(String p, Map<String,dynamic> b) async => (await c.post(p, b)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _pu(String p, Map<String,dynamic> b) async => (await c.put(p, b)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _pa(String p, Map<String,dynamic> b) async => (await c.patch(p, b)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _d(String p) async => (await c.delete(p)) as Map<String,dynamic>;

  List<dynamic> _list(Map<String,dynamic> r, List<String> keys) {
    for (final k in keys) { if (r[k] is List) return r[k] as List; }
    for (final v in r.values) { if (v is List) return v; }
    return [];
  }

  // Public generic HTTP wrappers — for ad-hoc screens that need flexible responses
  Future<dynamic> get(String path) async { try { return await c.get(path); } catch (_) { return null; } }
  Future<dynamic> post(String path, Map<String,dynamic> body) async { try { return await c.post(path, body); } catch (_) { return null; } }
  Future<dynamic> patch(String path, Map<String,dynamic> body) async { try { return await c.patch(path, body); } catch (_) { return null; } }

  // ── Dashboard ─────────────────────────────────────────────────────────────
  Future<Map<String,dynamic>?> overview() async { try { return await _g('/api/dashboard/overview'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> metrics() async { try { return await _g('/api/dashboard/metrics'); } catch (_) { return null; } }

  // ── Agents ────────────────────────────────────────────────────────────────
  Future<List> agents() async { try { final r = await _g('/api/agents'); return _list(r, ['data','agents']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> agentSummary(int id) async { try { return await _g('/api/agents/$id/summary'); } catch (_) { return null; } }
  Future<List> agentProcesses(int id) async { try { final r = await _g('/api/agents/$id/processes'); return _list(r, ['processes','data']); } catch (_) { return []; } }
  Future<List> agentConnections(int id) async { try { final r = await _g('/api/agents/$id/connections'); return _list(r, ['connections','data']); } catch (_) { return []; } }
  Future<List> agentPackages(int id) async { try { final r = await _g('/api/agents/$id/packages'); return _list(r, ['packages','data']); } catch (_) { return []; } }
  Future<List> agentVulns(int id) async { try { final r = await _g('/api/agents/$id/vulnerabilities'); return _list(r, ['vulnerabilities','data']); } catch (_) { return []; } }
  Future<List> agentTimeline(int id) async { try { final r = await _g('/api/agents/$id/timeline'); return _list(r, ['events','data']); } catch (_) { return []; } }
  Future<bool> queueTask(int agentId, String type, {Map<String,dynamic>? payload}) async { try { await _po('/api/tasks', {'agent_id': agentId, 'task_type': type, 'payload': payload ?? {}}); return true; } catch (_) { return false; } }
  Future<bool> killTree(int id, int pid) async { try { await _po('/api/agents/$id/kill-tree', {'pid': pid}); return true; } catch (_) { return false; } }
  Future<bool> memoryDump(int id) async { try { await _po('/api/agents/$id/memory-dump', {}); return true; } catch (_) { return false; } }
  Future<bool> processSnapshot(int id) async { try { await _po('/api/agents/$id/process-snapshot', {}); return true; } catch (_) { return false; } }

  // ── Network ───────────────────────────────────────────────────────────────
  Future<Map<String,dynamic>?> networkMap() async { try { return await _g('/api/network-map'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> attackPaths() async { try { return await _g('/api/attack-path'); } catch (_) { return null; } }

  // ── Alerts ────────────────────────────────────────────────────────────────
  Future<List> alerts({int page=1, int per=30, String sev='', String status='', String q=''}) async {
    try {
      var qs = 'page=$page&per_page=$per';
      if (sev.isNotEmpty) qs += '&severity=$sev';
      if (status.isNotEmpty) qs += '&status=$status';
      if (q.isNotEmpty) qs += '&search=${Uri.encodeComponent(q)}';
      final r = await _g('/api/alerts/paginated?$qs');
      return _list(r, ['alerts','data']);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> alertDetail(int id) async { try { return await _g('/api/alerts/$id'); } catch (_) { return null; } }
  Future<bool> ackAlert(int id, {String note=''}) async { try { await _po('/api/alerts/$id/acknowledge', {'note': note}); return true; } catch (_) { return false; } }
  Future<bool> resolveAlert(int id, {String note=''}) async { try { await _po('/api/alerts/$id/resolve', {'note': note}); return true; } catch (_) { return false; } }
  Future<bool> bulkAck(List<int> ids) async { try { await _po('/api/alerts/bulk-acknowledge', {'ids': ids}); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> alertInvestigation(int id) async { try { return await _g('/api/alerts/$id/investigate'); } catch (_) { return null; } }

  // ── Incidents ─────────────────────────────────────────────────────────────
  Future<List> incidents({int page=1, int per=20, String status=''}) async {
    try {
      var qs = 'page=$page&per_page=$per';
      if (status.isNotEmpty) qs += '&status=$status';
      final r = await _g('/api/incidents/paginated?$qs');
      return _list(r, ['incidents','data']);
    } catch (_) { return []; }
  }
  Future<bool> updateIncidentStatus(int id, String status) async { try { await _pu('/api/incidents/$id/status', {'status': status}); return true; } catch (_) { return false; } }
  Future<bool> addIncidentNote(int id, String note) async { try { await _po('/api/incidents/$id/notes', {'note': note}); return true; } catch (_) { return false; } }
  Future<List> incidentEvents(int id) async { try { final r = await _g('/api/incidents/$id/events'); return _list(r, ['events','data']); } catch (_) { return []; } }

  // ── UEBA ──────────────────────────────────────────────────────────────────
  // ueba/users → insider-threat scores contain the user list with risk scores
  Future<List> uebaUsers() async { try { final r = await _g('/api/insider-threat'); return _list(r, ['scores','users','data']); } catch (_) { return []; } }
  // ueba/events → threat audit events are the closest real-time equivalent
  Future<List> uebaEvents() async { try { final r = await _g('/api/audit-events/threats'); return _list(r, ['events','data']); } catch (_) { return []; } }
  Future<bool> triggerUEBA() async { try { await _po('/api/ueba/analyze', {}); return true; } catch (_) { return false; } }

  // ── Insider Threat ────────────────────────────────────────────────────────
  Future<List> insiderThreat() async { try { final r = await _g('/api/insider-threat'); return _list(r, ['scores','users','data']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> insiderSummary() async { try { return await _g('/api/insider-threat/summary'); } catch (_) { return null; } }

  // ── ITDR (AD Attacks / Cloud / etc.) ──────────────────────────────────────
  Future<List> itdrFindings({String category=''}) async {
    try {
      final qs = category.isNotEmpty ? '?type=$category' : '';
      final r = await _g('/api/itdr/findings$qs');
      return _list(r, ['findings','data']);
    } catch (_) { return []; }
  }
  Future<bool> updateItdrStatus(int id, String status) async { try { await _pa('/api/itdr/findings/$id/status', {'status': status}); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> itdrSummary() async { try { return await _g('/api/itdr/summary'); } catch (_) { return null; } }

  // ── Net Behavior ──────────────────────────────────────────────────────────
  Future<List> nbaAnomalies() async { try { final r = await _g('/api/nba/anomalies'); return _list(r, ['anomalies','data']); } catch (_) { return []; } }
  Future<bool> ackNbaAnomaly(int id) async { try { await _po('/api/nba/anomalies/$id/acknowledge', {}); return true; } catch (_) { return false; } }
  Future<bool> triggerNBA() async { try { await _po('/api/nba/analyze', {}); return true; } catch (_) { return false; } }

  // ── Behavioral ────────────────────────────────────────────────────────────
  Future<List> threatScores() async { try { final r = await _g('/api/threat/scores'); return _list(r, ['scores','data']); } catch (_) { return []; } }
  Future<List> threatFleet() async { try { final r = await _g('/api/threat/fleet'); return _list(r, ['agents','data']); } catch (_) { return []; } }
  Future<bool> ackThreatFinding(int id) async { try { await _po('/api/threat/findings/$id/acknowledge', {}); return true; } catch (_) { return false; } }

  // ── Live Logs ─────────────────────────────────────────────────────────────
  Future<List> liveEvents() async { try { final r = await _g('/api/audit-events/threats'); return _list(r, ['events','data']); } catch (_) { return []; } }

  // ── Log Search ────────────────────────────────────────────────────────────
  Future<List> searchLogs({String q='', String agentId='', String level='', int limit=50}) async {
    try {
      var qs = 'limit=$limit';
      if (q.isNotEmpty) qs += '&q=${Uri.encodeComponent(q)}';
      if (agentId.isNotEmpty) qs += '&agent_id=$agentId';
      if (level.isNotEmpty) qs += '&level=$level';
      final r = await _g('/api/logs/search?$qs');
      return _list(r, ['logs','results','data']);
    } catch (_) { return []; }
  }
  Future<List> savedSearches() async { try { final r = await _g('/api/logs/searches'); return _list(r, ['searches','data']); } catch (_) { return []; } }
  Future<bool> saveSearch(String name, String query) async { try { await _po('/api/logs/searches', {'name': name, 'query': query, 'filters': {}}); return true; } catch (_) { return false; } }
  Future<bool> deleteSavedSearch(int id) async { try { await _d('/api/logs/searches/$id'); return true; } catch (_) { return false; } }
  Future<List> runSavedSearch(int id) async { try { final r = await _po('/api/logs/searches/$id/run', {}); return _list(r, ['logs','results','data']); } catch (_) { return []; } }

  // ── Log Sources ───────────────────────────────────────────────────────────
  Future<List> logSources() async { try { final r = await _g('/api/log-sources'); return _list(r, ['sources','data']); } catch (_) { return []; } }
  Future<bool> createLogSource(Map<String,dynamic> body) async { try { await _po('/api/log-sources', body); return true; } catch (_) { return false; } }
  Future<bool> updateLogSource(int id, Map<String,dynamic> body) async { try { await _pu('/api/log-sources/$id', body); return true; } catch (_) { return false; } }
  Future<bool> deleteLogSource(int id) async { try { await _d('/api/log-sources/$id'); return true; } catch (_) { return false; } }

  // ── Hunt ─────────────────────────────────────────────────────────────────
  Future<List> huntTemplates() async { try { final r = await _g('/api/hunt/templates'); return _list(r, ['templates','data']); } catch (_) { return []; } }
  Future<bool> createHuntTemplate(Map<String,dynamic> b) async { try { await _po('/api/hunt/templates', b); return true; } catch (_) { return false; } }
  Future<bool> deleteHuntTemplate(int id) async { try { await _d('/api/hunt/templates/$id'); return true; } catch (_) { return false; } }
  Future<List> huntRuns() async { try { final r = await _g('/api/hunt/runs'); return _list(r, ['runs','data']); } catch (_) { return []; } }
  Future<bool> executeHunt(int templateId, List<int> agentIds) async { try { await _po('/api/hunt/execute', {'template_id': templateId, 'agent_ids': agentIds}); return true; } catch (_) { return false; } }

  // ── Alert Clusters ────────────────────────────────────────────────────────
  Future<List> clusters() async { try { final r = await _g('/api/clusters'); return _list(r, ['clusters','data']); } catch (_) { return []; } }
  Future<List> clusterAlerts(int id) async { try { final r = await _g('/api/clusters/$id/alerts'); return _list(r, ['alerts','data']); } catch (_) { return []; } }
  Future<bool> suppressCluster(int id) async { try { await _po('/api/clusters/$id/suppress', {}); return true; } catch (_) { return false; } }
  Future<bool> triggerClustering() async { try { await _po('/api/clusters/analyze', {}); return true; } catch (_) { return false; } }

  // ── Correlation ───────────────────────────────────────────────────────────
  Future<List> correlationRules() async { try { final r = await _g('/api/correlation/rules'); return _list(r, ['rules','data']); } catch (_) { return []; } }
  Future<bool> createCorrelationRule(Map<String,dynamic> b) async { try { await _po('/api/correlation/rules', b); return true; } catch (_) { return false; } }
  Future<bool> updateCorrelationRule(int id, Map<String,dynamic> b) async { try { await _pu('/api/correlation/rules/$id', b); return true; } catch (_) { return false; } }
  Future<bool> toggleCorrelationRule(int id) async { try { await _pa('/api/correlation/rules/$id/toggle', {}); return true; } catch (_) { return false; } }
  Future<bool> deleteCorrelationRule(int id) async { try { await _d('/api/correlation/rules/$id'); return true; } catch (_) { return false; } }
  Future<List> correlationMatches() async { try { final r = await _g('/api/correlation/matches'); return _list(r, ['matches','data']); } catch (_) { return []; } }

  // ── Suppression ───────────────────────────────────────────────────────────
  Future<List> suppressionRules() async { try { final r = await _g('/api/suppression/rules'); return _list(r, ['rules','data']); } catch (_) { return []; } }
  Future<bool> createSuppressionRule(Map<String,dynamic> b) async { try { await _po('/api/suppression/rules', b); return true; } catch (_) { return false; } }
  Future<bool> toggleSuppression(int id) async { try { await _pa('/api/suppression/rules/$id/toggle', {}); return true; } catch (_) { return false; } }
  Future<bool> deleteSuppression(int id) async { try { await _d('/api/suppression/rules/$id'); return true; } catch (_) { return false; } }

  // ── Cases ─────────────────────────────────────────────────────────────────
  Future<List> cases({String status=''}) async {
    try { final r = await _g('/api/cases${status.isNotEmpty ? "?status=$status" : ""}'); return _list(r, ['cases','data']); } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> caseDetail(int id) async { try { return await _g('/api/cases/$id'); } catch (_) { return null; } }
  Future<bool> createCase(Map<String,dynamic> b) async { try { await _po('/api/cases', b); return true; } catch (_) { return false; } }
  Future<bool> updateCase(int id, Map<String,dynamic> b) async { try { await _pu('/api/cases/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteCase(int id) async { try { await _d('/api/cases/$id'); return true; } catch (_) { return false; } }
  Future<bool> addCaseComment(int id, String body) async { try { await _po('/api/cases/$id/comments', {'body': body}); return true; } catch (_) { return false; } }
  Future<bool> linkAlertToCase(int caseId, int alertId) async { try { await _po('/api/cases/$caseId/alerts', {'alert_id': alertId}); return true; } catch (_) { return false; } }

  // ── Playbooks ─────────────────────────────────────────────────────────────
  Future<List> playbooks() async { try { final r = await _g('/api/playbooks'); return _list(r, ['playbooks','data']); } catch (_) { return []; } }
  Future<bool> createPlaybook(Map<String,dynamic> b) async { try { await _po('/api/playbooks', b); return true; } catch (_) { return false; } }
  Future<bool> updatePlaybook(int id, Map<String,dynamic> b) async { try { await _pu('/api/playbooks/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deletePlaybook(int id) async { try { await _d('/api/playbooks/$id'); return true; } catch (_) { return false; } }
  Future<bool> enablePlaybook(int id) async { try { await _pa('/api/playbooks/$id/enable', {}); return true; } catch (_) { return false; } }
  Future<bool> disablePlaybook(int id) async { try { await _pa('/api/playbooks/$id/disable', {}); return true; } catch (_) { return false; } }
  // /api/playbooks/:id/execute doesn't exist — enable the playbook as the trigger action
  Future<bool> triggerPlaybook(int id, Map<String,dynamic> payload) async { try { await _pa('/api/playbooks/$id/enable', {}); return true; } catch (_) { return false; } }
  Future<List> playbookExecutions() async { try { final r = await _g('/api/playbook-executions'); return _list(r, ['executions','data']); } catch (_) { return []; } }

  // ── Approvals ─────────────────────────────────────────────────────────────
  Future<List> pendingApprovals() async { try { final r = await _g('/api/tasks/pending-approval'); return _list(r, ['tasks','data']); } catch (_) { return []; } }
  Future<bool> approveTask(int id) async { try { await _po('/api/tasks/$id/approve', {}); return true; } catch (_) { return false; } }
  Future<bool> rejectTask(int id, String reason) async { try { await _po('/api/tasks/$id/reject', {'reason': reason}); return true; } catch (_) { return false; } }

  // ── Vulnerabilities ───────────────────────────────────────────────────────
  Future<List> vulnQueue() async { try { final r = await _g('/api/vulns/priority-queue'); return _list(r, ['vulns','vulnerabilities','data']); } catch (_) { return []; } }
  Future<bool> updatePatchStatus(int id, String status) async { try { await _pa('/api/vulns/$id/patch-status', {'status': status}); return true; } catch (_) { return false; } }
  Future<bool> refreshVulnPriorities() async { try { await _po('/api/vulns/refresh-priorities', {}); return true; } catch (_) { return false; } }
  Future<List> agentVulnerabilities(int agentId) async { try { final r = await _g('/api/agents/$agentId/vulnerabilities'); return _list(r, ['vulnerabilities','data']); } catch (_) { return []; } }

  // ── Quarantine ────────────────────────────────────────────────────────────
  Future<List> quarantine() async { try { final r = await _g('/api/quarantine'); return _list(r, ['files','data']); } catch (_) { return []; } }
  // /api/quarantine/stats does not exist — derive stats from the list instead
  Future<Map<String,dynamic>?> quarantineStats() async => null;
  Future<bool> releaseQuarantine(int id) async { try { await _d('/api/quarantine/$id'); return true; } catch (_) { return false; } }

  // ── Firewall ──────────────────────────────────────────────────────────────
  Future<List> firewallRules({String group=''}) async {
    try { final r = await _g('/api/firewall/rules${group.isNotEmpty ? "?group=$group" : ""}'); return _list(r, ['rules','data']); } catch (_) { return []; }
  }
  // /api/firewall/groups and /api/firewall/stats don't exist in backend
  Future<List> firewallGroups() async => [];
  Future<Map<String,dynamic>?> firewallStats() async => null;
  Future<bool> createFirewallRule(Map<String,dynamic> b) async { try { await _po('/api/firewall/rules', b); return true; } catch (_) { return false; } }
  Future<bool> updateFirewallRule(int id, Map<String,dynamic> b) async { try { await _pu('/api/firewall/rules/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteFirewallRule(int id) async { try { await _d('/api/firewall/rules/$id'); return true; } catch (_) { return false; } }
  Future<bool> syncFirewall() async { try { await _po('/api/firewall/sync', {}); return true; } catch (_) { return false; } }

  // ── Scheduled Tasks ───────────────────────────────────────────────────────
  Future<List> scheduledTasks() async { try { final r = await _g('/api/scheduler/tasks'); return _list(r, ['tasks','data']); } catch (_) { return []; } }
  Future<bool> createScheduledTask(Map<String,dynamic> b) async { try { await _po('/api/scheduler/tasks', b); return true; } catch (_) { return false; } }
  Future<bool> toggleScheduledTask(int id) async { try { await _pa('/api/scheduler/tasks/$id/toggle', {}); return true; } catch (_) { return false; } }
  Future<bool> runScheduledTask(int id) async { try { await _po('/api/scheduler/tasks/$id/run', {}); return true; } catch (_) { return false; } }
  Future<bool> deleteScheduledTask(int id) async { try { await _d('/api/scheduler/tasks/$id'); return true; } catch (_) { return false; } }

  // ── DFIR ──────────────────────────────────────────────────────────────────
  Future<List> dfirCollections() async { try { final r = await _g('/api/dfir/collections'); return _list(r, ['collections','data']); } catch (_) { return []; } }
  Future<bool> triggerDfir(int agentId, String type) async { try { await _po('/api/dfir/collections', {'agent_id': agentId, 'collection_type': type, 'options': {}}); return true; } catch (_) { return false; } }
  Future<List> dfirArtifacts(int id) async { try { final r = await _g('/api/dfir/collections/$id/artifacts'); return _list(r, ['artifacts','data']); } catch (_) { return []; } }

  // ── Scripts (via Sigma rules — no dedicated scripts API) ─────────────────
  Future<List> scriptTemplates() async { try { final r = await _g('/api/sigma/rules'); return _list(r, ['rules','data']); } catch (_) { return []; } }
  Future<List> scriptHistory() async { try { final r = await _g('/api/hunt/runs'); return _list(r, ['runs','data']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> runScript(int agentId, String script, String interpreter) async {
    try { return await _po('/api/scripts/run', {'agent_id': agentId, 'script': script, 'interpreter': interpreter}); } catch (e) { return {'error': e.toString()}; }
  }
  Future<Map<String,dynamic>?> scriptResult(String taskId) async { try { return await _g('/api/agents/$taskId/tasks'); } catch (_) { return null; } }

  // ── Assets ────────────────────────────────────────────────────────────────
  Future<List> assets() async { try { final r = await _g('/api/assets'); return _list(r, ['assets','data']); } catch (_) { return []; } }
  Future<bool> createAsset(Map<String,dynamic> b) async { try { await _po('/api/assets', b); return true; } catch (_) { return false; } }
  Future<bool> updateAsset(int id, Map<String,dynamic> b) async { try { await _pu('/api/assets/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteAsset(int id) async { try { await _d('/api/assets/$id'); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> platformSummary() async { try { return await _g('/api/assets/platform-summary'); } catch (_) { return null; } }

  // ── MDM ───────────────────────────────────────────────────────────────────
  Future<List> mdmDevices() async { try { final r = await _g('/api/mdm/devices'); return _list(r, ['devices','data']); } catch (_) { return []; } }
  Future<bool> mdmBlock(int id) async { try { await _po('/api/mdm/devices/$id/block', {}); return true; } catch (_) { return false; } }
  Future<bool> mdmUnblock(int id) async { try { await _po('/api/mdm/devices/$id/unblock', {}); return true; } catch (_) { return false; } }
  Future<bool> mdmUnenroll(int id) async { try { await _d('/api/mdm/devices/$id'); return true; } catch (_) { return false; } }
  Future<bool> mdmCommand(int deviceId, String cmd, [Map<String,dynamic>? payload]) async { try { await _po('/api/mdm/devices/$deviceId/commands', {'command_type': cmd, 'payload': payload ?? {}}); return true; } catch (_) { return false; } }
  Future<List> mdmTokens() async { try { final r = await _g('/api/mdm/enrollment-tokens'); return _list(r, ['tokens','data']); } catch (_) { return []; } }
  Future<List> mdmEnrollments() => mdmTokens();
  Future<bool> createMdmToken(String label, String platform) async { try { await _po('/api/mdm/enrollment-tokens', {'label': label, 'platform': platform}); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> createEnrollmentToken(String type) async { try { return await _po('/api/mdm/enrollment-tokens', {'label': 'Mobile Admin', 'platform': 'android', 'enrollment_type': type}); } catch (_) { return null; } }
  Future<bool> revokeMdmToken(int id) async { try { await _d('/api/mdm/enrollment-tokens/$id'); return true; } catch (_) { return false; } }
  Future<bool> revokeEnrollment(int id) => revokeMdmToken(id);

  // ── Sigma/YARA/JA3/IOC ───────────────────────────────────────────────────
  Future<List> sigmaRules() async { try { final r = await _g('/api/sigma/rules'); return _list(r, ['rules','data']); } catch (_) { return []; } }
  Future<bool> createSigma(Map<String,dynamic> b) async { try { await _po('/api/sigma/rules', b); return true; } catch (_) { return false; } }
  Future<bool> updateSigma(int id, Map<String,dynamic> b) async { try { await _pu('/api/sigma/rules/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteSigma(int id) async { try { await _d('/api/sigma/rules/$id'); return true; } catch (_) { return false; } }
  Future<bool> toggleSigma(int id, bool enable) async { try { await _pa('/api/sigma/rules/$id/${enable ? "enable" : "disable"}', {}); return true; } catch (_) { return false; } }

  Future<List> yaraRules() async { try { final r = await _g('/api/yara/rules'); return _list(r, ['rules','data']); } catch (_) { return []; } }
  Future<bool> createYara(Map<String,dynamic> b) async { try { await _po('/api/yara/rules', b); return true; } catch (_) { return false; } }
  Future<bool> updateYara(int id, Map<String,dynamic> b) async { try { await _pu('/api/yara/rules/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteYara(int id) async { try { await _d('/api/yara/rules/$id'); return true; } catch (_) { return false; } }
  Future<bool> toggleYara(int id, bool enable) async { try { await _pa('/api/yara/rules/$id/${enable ? "enable" : "disable"}', {}); return true; } catch (_) { return false; } }

  Future<List> ja3Fingerprints() async { try { final r = await _g('/api/ja3/fingerprints'); return _list(r, ['fingerprints','data']); } catch (_) { return []; } }
  Future<bool> createJa3(Map<String,dynamic> b) async { try { await _po('/api/ja3/fingerprints', b); return true; } catch (_) { return false; } }
  Future<bool> deleteJa3(int id) async { try { await _d('/api/ja3/fingerprints/$id'); return true; } catch (_) { return false; } }

  Future<List> iocs() async { try { final r = await _g('/api/iocs'); return _list(r, ['iocs','data']); } catch (_) { return []; } }
  Future<bool> createIoc(Map<String,dynamic> b) async { try { await _po('/api/iocs', b); return true; } catch (_) { return false; } }
  Future<bool> updateIoc(int id, Map<String,dynamic> b) async { try { await _pu('/api/iocs/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteIoc(int id) async { try { await _d('/api/iocs/$id'); return true; } catch (_) { return false; } }
  Future<bool> toggleIoc(int id, bool enable) async { try { await _pa('/api/iocs/$id/${enable ? "enable" : "disable"}', {}); return true; } catch (_) { return false; } }

  Future<List> threatFeeds() async { try { final r = await _g('/api/threat-feeds'); return _list(r, ['feeds','data']); } catch (_) { return []; } }
  Future<bool> createThreatFeed(Map<String,dynamic> b) async { try { await _po('/api/threat-feeds', b); return true; } catch (_) { return false; } }
  Future<bool> updateThreatFeed(int id, Map<String,dynamic> b) async { try { await _pu('/api/threat-feeds/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteThreatFeed(int id) async { try { await _d('/api/threat-feeds/$id'); return true; } catch (_) { return false; } }
  Future<bool> syncThreatFeed(int id) async { try { await _po('/api/threat-feeds/$id/sync', {}); return true; } catch (_) { return false; } }

  // ── Threat Actors ─────────────────────────────────────────────────────────
  Future<List> threatActors() async { try { final r = await _g('/api/threat-actors'); return _list(r, ['actors','data']); } catch (_) { return []; } }
  Future<bool> createThreatActor(Map<String,dynamic> b) async { try { await _po('/api/threat-actors', b); return true; } catch (_) { return false; } }
  Future<bool> deleteThreatActor(int id) async { try { await _d('/api/threat-actors/$id'); return true; } catch (_) { return false; } }

  // ── Compliance/Reports ────────────────────────────────────────────────────
  Future<List> complianceReports() async { try { final r = await _g('/api/compliance/reports'); return _list(r, ['reports','data']); } catch (_) { return []; } }
  Future<List> reports() => complianceReports();
  Future<bool> createReport(Map<String,dynamic> b) async { try { await _po('/api/compliance/reports', b); return true; } catch (_) { return false; } }
  // /api/compliance/reports/:id/generate doesn't exist — create a fresh report for same type
  Future<bool> generateReport(int id) async { try { await _po('/api/compliance/reports', {'regenerate_from_id': id}); return true; } catch (_) { return false; } }
  Future<bool> deleteReport(int id) async { try { await _d('/api/compliance/reports/$id'); return true; } catch (_) { return false; } }
  Future<List> frameworkAssessments() async { try { final r = await _g('/api/framework-compliance'); return _list(r, ['assessments','frameworks','data']); } catch (_) { return []; } }
  Future<List> frameworks() => frameworkAssessments();
  // No framework-compliance refresh endpoint — refresh risk posture as proxy
  Future<bool> refreshFrameworks() async { try { await _po('/api/risk-posture/refresh', {}); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> executiveMetrics() async { try { return await _g('/api/executive/metrics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> executiveSummary() => executiveMetrics();
  Future<Map<String,dynamic>?> socMetrics() async { try { return await _g('/api/soc/metrics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> riskPosture() async { try { return await _g('/api/risk-posture'); } catch (_) { return null; } }
  Future<bool> refreshRiskPosture() async { try { await _po('/api/risk-posture/refresh', {}); return true; } catch (_) { return false; } }

  // ── AI ────────────────────────────────────────────────────────────────────
  Future<Map<String,dynamic>?> aiChat(String message, {String? sessionId}) async {
    try {
      final body = <String,dynamic>{'message': message, 'context': ''};
      if (sessionId != null) body['session_id'] = sessionId;
      return await _po('/api/ai/chat', body);
    } catch (_) { return null; }
  }
  Future<List> chatHistory() async { try { final r = await _g('/api/ai/chat/history'); return _list(r, ['messages','history','data']); } catch (_) { return []; } }
  Future<bool> clearChatHistory() async { try { await _d('/api/ai/chat/history'); return true; } catch (_) { return false; } }
  Future<bool> triageAlert(int id) async { try { await _po('/api/ai/triage/$id', {}); return true; } catch (_) { return false; } }

  // ── Settings ──────────────────────────────────────────────────────────────
  Future<List> users() async { try { final r = await _g('/api/users'); return _list(r, ['users','data']); } catch (_) { return []; } }
  Future<bool> createUser(Map<String,dynamic> b) async { try { await _po('/api/users', b); return true; } catch (_) { return false; } }
  Future<bool> inviteUser(String email, String role) async { try { await _po('/api/users/invite', {'email': email, 'role': role}); return true; } catch (_) { return false; } }
  // No admin password reset endpoint — trigger forgot-password flow by email instead
  Future<bool> resetUserPassword(int id) async { try { await _po('/api/auth/forgot-password', {'user_id': id}); return true; } catch (_) { return false; } }
  Future<bool> updateUserRole(int id, String role) async { try { await _pu('/api/users/$id/role', {'role': role}); return true; } catch (_) { return false; } }
  Future<bool> toggleUser(int id) async { try { await _pa('/api/users/$id/toggle', {}); return true; } catch (_) { return false; } }
  Future<bool> deleteUser(int id) async { try { await _d('/api/users/$id'); return true; } catch (_) { return false; } }

  Future<List> apiKeys() async { try { final r = await _g('/api/api-keys'); return _list(r, ['keys','api_keys','data']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> createApiKey(Map<String,dynamic> b) async { try { return await _po('/api/api-keys', b); } catch (_) { return null; } }
  Future<bool> deleteApiKey(int id) async { try { await _d('/api/api-keys/$id'); return true; } catch (_) { return false; } }
  Future<bool> revokeApiKey(int id) => deleteApiKey(id);

  Future<List> integrations() async { try { final r = await _g('/api/integrations'); return _list(r, ['integrations','data']); } catch (_) { return []; } }
  // No toggle endpoint — save enabled flag via PUT /api/integrations/:name
  Future<bool> toggleIntegration(String name, bool enable) async { try { await _pu('/api/integrations/$name', {'enabled': enable}); return true; } catch (_) { return false; } }
  Future<bool> saveIntegration(String name, Map<String,dynamic> config) async { try { await _pu('/api/integrations/$name', {'config': config}); return true; } catch (_) { return false; } }
  Future<bool> testIntegration(String name) async { try { await _po('/api/integrations/$name/test', {}); return true; } catch (_) { return false; } }

  Future<List> customRoles() async { try { final r = await _g('/api/custom-roles'); return _list(r, ['roles','data']); } catch (_) { return []; } }
  Future<bool> createCustomRole(Map<String,dynamic> b) async { try { await _po('/api/custom-roles', b); return true; } catch (_) { return false; } }
  Future<bool> deleteCustomRole(int id) async { try { await _d('/api/custom-roles/$id'); return true; } catch (_) { return false; } }

  // ── Deception (Canary + Honeyport) ────────────────────────────────────────
  Future<List> canaryTokens() async { try { final r = await _g('/api/canary/tokens'); return _list(r, ['tokens','data']); } catch (_) { return []; } }
  Future<bool> createCanary(Map<String,dynamic> b) async { try { await _po('/api/canary/tokens', b); return true; } catch (_) { return false; } }
  Future<bool> deleteCanary(int id) async { try { await _d('/api/canary/tokens/$id'); return true; } catch (_) { return false; } }
  Future<bool> toggleCanary(int id) async { try { await _pa('/api/canary/tokens/$id/toggle', {}); return true; } catch (_) { return false; } }
  Future<List> canaryTrips() async { try { final r = await _g('/api/canary/trips'); return _list(r, ['trips','data']); } catch (_) { return []; } }
  Future<List> honeyports() async { try { final r = await _g('/api/honeyports'); return _list(r, ['honeyports','data']); } catch (_) { return []; } }
  Future<bool> createHoneyport(Map<String,dynamic> b) async { try { await _po('/api/honeyports', b); return true; } catch (_) { return false; } }
  Future<bool> deleteHoneyport(int id) async { try { await _d('/api/honeyports/$id'); return true; } catch (_) { return false; } }

  // ── Events / Timeline ────────────────────────────────────────────────────
  // /api/events doesn't exist — use audit-events/threats for real-time event feed
  Future<List> events({int limit = 100, String type = ''}) async {
    try {
      final r = await _g('/api/audit-events/threats');
      return _list(r, ['events', 'data']);
    } catch (_) { return []; }
  }

  // ── Tenants ───────────────────────────────────────────────────────────────
  Future<List> tenants() async { try { final r = await _g('/api/platform/tenants'); return _list(r, ['tenants','data']); } catch (_) { return []; } }
  Future<bool> createTenant(Map<String,dynamic> b) async { try { await _po('/api/platform/tenants', b); return true; } catch (_) { return false; } }
  Future<bool> toggleTenant(int id) async { try { await _pa('/api/platform/tenants/$id/toggle', {}); return true; } catch (_) { return false; } }
}
