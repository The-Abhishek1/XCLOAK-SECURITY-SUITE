import 'dart:convert';
import 'package:http/http.dart' as http;
import '../services/api_client.dart';
import '../services/secure_storage.dart';

class AdminUnauthorizedException implements Exception {
  final String message;
  const AdminUnauthorizedException(this.message);
  @override String toString() => message;
}

/// Thrown by [DashboardApi.login] when the account has TOTP enabled —
/// credentials were correct, but login isn't complete yet. Callers should
/// prompt for the 6-digit code and call [DashboardApi.completeTOTPLogin]
/// with [tempToken].
class Needs2FAException implements Exception {
  final String tempToken;
  const Needs2FAException(this.tempToken);
  @override String toString() => 'MFA code required to complete login';
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

    if (loginRes.statusCode < 200 || loginRes.statusCode >= 300) {
      // Surface the backend's real message — a 403 here can mean either bad
      // credentials or an IP-allowlist rejection, and a 429 means the
      // account is temporarily locked (with the real lockout duration in
      // the message). Collapsing all of these into "Invalid credentials"
      // hid the actual reason and made lockouts look like a typo'd password.
      String msg = 'Login failed (${loginRes.statusCode})';
      try {
        final body = jsonDecode(loginRes.body) as Map<String, dynamic>;
        if (body['error'] is String && (body['error'] as String).isNotEmpty) msg = body['error'];
      } catch (_) {}
      if (loginRes.statusCode == 401 || loginRes.statusCode == 403) {
        throw AdminUnauthorizedException(msg);
      }
      throw ApiException(loginRes.statusCode, msg);
    }

    // 2 — Extract token from JSON body (backend returns it for Dart/mobile
    //     clients), or detect that this account needs a second 2FA step —
    //     the backend responds 200 with needs_2fa+temp_token and no token
    //     at all in that case, previously indistinguishable from "server
    //     didn't return a token" and blocking 2FA accounts from mobile
    //     login entirely.
    Map<String, dynamic> json = {};
    try { json = jsonDecode(loginRes.body) as Map<String, dynamic>; } catch (_) {}

    if (json['needs_2fa'] == true) {
      final tempToken = (json['temp_token'] ?? '').toString();
      if (tempToken.isEmpty) {
        throw Exception('Server requested 2FA but returned no temp_token.');
      }
      throw Needs2FAException(tempToken);
    }

    String rawToken = (json['token'] ?? '').toString();

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

    return _finishLogin(serverUrl, rawToken, fallbackEmail: email);
  }

  /// Second step of a 2FA login — exchanges [tempToken] + the 6-digit
  /// authenticator [code] for a real session, same as [login]'s tail.
  static Future<DashboardApi> completeTOTPLogin(String serverUrl, String tempToken, String code) async {
    final res = await http.post(
      Uri.parse('$serverUrl/api/auth/login/2fa'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'temp_token': tempToken, 'code': code}),
    ).timeout(const Duration(seconds: 15));

    if (res.statusCode < 200 || res.statusCode >= 300) {
      String msg = 'Invalid code';
      try {
        final body = jsonDecode(res.body) as Map<String, dynamic>;
        if (body['error'] is String && (body['error'] as String).isNotEmpty) msg = body['error'];
      } catch (_) {}
      throw AdminUnauthorizedException(msg);
    }

    String rawToken = '';
    try {
      final json = jsonDecode(res.body) as Map<String, dynamic>;
      rawToken = (json['token'] ?? '').toString();
    } catch (_) {}
    if (rawToken.isEmpty) {
      final setCookie = res.headers['set-cookie'] ?? '';
      final m = RegExp(r'(?:^|[\s,])token=([^;,\s]+)').firstMatch(setCookie);
      rawToken = m?.group(1) ?? '';
    }
    if (rawToken.isEmpty) {
      throw Exception('Server did not return an auth token after 2FA.');
    }

    return _finishLogin(serverUrl, rawToken);
  }

  /// Shared tail of both login paths: verify admin role via the profile
  /// endpoint, persist the session, and return a ready-to-use client.
  static Future<DashboardApi> _finishLogin(String serverUrl, String rawToken, {String? fallbackEmail}) async {
    final cookie = 'token=$rawToken';

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

    final displayEmail = (profile['email'] ?? fallbackEmail ?? '').toString();
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

      return DashboardApi._(client);
    } catch (_) {
      return null;
    }
  }
  DashboardApi._(this.c);
  final ApiClient c;

  // ── helpers ───────────────────────────────────────────────────────────────
  // _g deliberately returns `dynamic`, not `Map<String,dynamic>` — many list
  // endpoints respond with a bare JSON array rather than an object, and a
  // forced cast here would throw before _list() ever got a chance to look at
  // it. Every call site already runs inside try/catch, so an unexpected
  // shape on a single-object endpoint still fails safely, same as before.
  Future<dynamic> _g(String p) async => await c.get(p);
  Future<Map<String,dynamic>> _po(String p, Map<String,dynamic> b) async => (await c.post(p, b)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _pu(String p, Map<String,dynamic> b) async => (await c.put(p, b)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _pa(String p, Map<String,dynamic> b) async => (await c.patch(p, b)) as Map<String,dynamic>;
  Future<Map<String,dynamic>> _d(String p) async => (await c.delete(p)) as Map<String,dynamic>;

  // Tolerates both response shapes: a bare JSON array, or an object with the
  // list nested under one of `keys` (or any key, as a last resort).
  List<dynamic> _list(dynamic r, List<String> keys) {
    if (r is List) return r;
    if (r is! Map<String,dynamic>) return [];
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

  // ── Install Tokens (Deploy Agent) ────────────────────────────────────────
  // Success body: {token, expires_in, label}. Surfaces the backend's error
  // message on failure (e.g. missing manage_integrations permission) instead
  // of a bare bool, since the wizard needs to show it verbatim.
  Future<Map<String,dynamic>?> generateInstallToken(String label) async {
    try { return await _po('/api/integrations/install-tokens', {'label': label}); } catch (e) { return {'error': e.toString()}; }
  }
  Future<List> installTokens() async { try { final r = await _g('/api/integrations/install-tokens'); return _list(r, ['tokens','data']); } catch (_) { return []; } }

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
  Future<bool> updateIncidentSeverity(int id, String severity) async { try { await _pa('/api/incidents/$id/severity', {'severity': severity}); return true; } catch (_) { return false; } }
  Future<bool> addIncidentNote(int id, String note) async { try { await _po('/api/incidents/$id/notes', {'note': note}); return true; } catch (_) { return false; } }
  Future<List> incidentEvents(int id) async { try { final r = await _g('/api/incidents/$id/events'); return _list(r, ['events','data']); } catch (_) { return []; } }

  // ── UEBA ──────────────────────────────────────────────────────────────────
  // ueba/users → insider-threat scores contain the user list with risk scores
  Future<List> uebaUsers() async { try { final r = await _g('/api/insider-threat'); return _list(r, ['scores','users','data']); } catch (_) { return []; } }
  // ueba/events → threat audit events are the closest real-time equivalent
  Future<List> uebaEvents() async { try { final r = await _g('/api/audit-events/threats'); return _list(r, ['events','data']); } catch (_) { return []; } }
  Future<bool> triggerUEBA() async { try { await _po('/api/ueba/analyze', {}); return true; } catch (_) { return false; } }
  // Only "force_logout" has a real effect — every other action string is
  // explicitly rejected server-side (UEBAResponseAction, ueba_enterprise.go)
  // to avoid faking disable_user/isolate_endpoint/etc with zero backend effect.
  Future<bool> forceLogoutUebaUser(String username) async { try { await _po('/api/ueba/users/$username/response-action', {'action': 'force_logout'}); return true; } catch (_) { return false; } }
  Future<bool> addUebaWatchlist(String username, {String category = 'general'}) async { try { await _po('/api/ueba/watchlist', {'username': username, 'category': category}); return true; } catch (_) { return false; } }
  Future<bool> removeUebaWatchlist(String username) async { try { await _d('/api/ueba/watchlist/$username'); return true; } catch (_) { return false; } }

  // ── Insider Threat ────────────────────────────────────────────────────────
  Future<List> insiderThreat() async { try { final r = await _g('/api/insider-threat'); return _list(r, ['scores','users','data']); } catch (_) { return []; } }
  // GetInsiderThreatSummary (api/insider_threat.go:74) returns a bare array
  // of {username, score, risk_level} rows, not a {high_risk,medium_risk,
  // low_risk} object — the implicit Map cast used to throw here every time
  // (silently caught), so the summary was always null and the UI's KPI
  // cards always showed 0. Bucket the real rows by risk_level ourselves.
  Future<Map<String,dynamic>> insiderSummary() async {
    try {
      final r = await _g('/api/insider-threat/summary');
      final rows = _list(r, []);
      int high = 0, medium = 0, low = 0;
      for (final row in rows) {
        switch ((row['risk_level'] ?? '').toString().toLowerCase()) {
          case 'high':     high++;   break;
          case 'medium':   medium++; break;
          default:         low++;
        }
      }
      return {'high_risk': high, 'medium_risk': medium, 'low_risk': low};
    } catch (_) {
      return {'high_risk': 0, 'medium_risk': 0, 'low_risk': 0};
    }
  }
  // Same real-effect-only restriction as UEBA's response-action.
  Future<bool> forceLogoutInsiderUser(String username) async { try { await _po('/api/insider-threat/users/$username/response-action', {'action': 'force_logout'}); return true; } catch (_) { return false; } }
  Future<bool> addInsiderWatchlist(String username, {String category = 'general'}) async { try { await _po('/api/insider-threat/watchlist', {'username': username, 'category': category}); return true; } catch (_) { return false; } }
  Future<bool> removeInsiderWatchlist(String username) async { try { await _d('/api/insider-threat/watchlist/$username'); return true; } catch (_) { return false; } }

  // ── ITDR (AD Attacks / Cloud / etc.) ──────────────────────────────────────
  Future<List> itdrFindings({String category=''}) async {
    try {
      final qs = category.isNotEmpty ? '?type=$category' : '';
      final r = await _g('/api/itdr/findings$qs');
      return _list(r, ['findings','data']);
    } catch (_) { return []; }
  }
  Future<bool> updateItdrStatus(int id, String status) async { try { await _pa('/api/itdr/findings/$id/status', {'status': status}); return true; } catch (_) { return false; } }

  // ── Net Behavior ──────────────────────────────────────────────────────────
  Future<List> nbaAnomalies() async { try { final r = await _g('/api/nba/anomalies'); return _list(r, ['anomalies','data']); } catch (_) { return []; } }
  Future<bool> ackNbaAnomaly(int id) async { try { await _po('/api/nba/anomalies/$id/acknowledge', {}); return true; } catch (_) { return false; } }
  Future<bool> triggerNBA() async { try { await _po('/api/nba/analyze', {}); return true; } catch (_) { return false; } }

  // ── DPI (Deep Inspection) ────────────────────────────────────────────────
  Future<Map<String,dynamic>?> dpiOverview({int hours = 24}) async { try { return await _g('/api/dpi/overview?hours=$hours') as Map<String,dynamic>; } catch (_) { return null; } }
  Future<List> dpiSessions({int hours = 1, int limit = 100}) async { try { final r = await _g('/api/dpi/sessions?hours=$hours&limit=$limit'); return _list(r, ['sessions']); } catch (_) { return []; } }
  Future<List> dpiFiles({int hours = 24}) async { try { final r = await _g('/api/dpi/files?hours=$hours'); return _list(r, ['files']); } catch (_) { return []; } }
  // DLPFinding's real column is `category` (aliased in SQL from finding_type) — not `finding_type`.
  Future<List> dpiDlp({int hours = 24}) async { try { final r = await _g('/api/dpi/dlp?hours=$hours'); return _list(r, ['findings']); } catch (_) { return []; } }
  Future<List> dpiProtocolAnomalies({int hours = 24}) async { try { final r = await _g('/api/dpi/protocol-anomalies?hours=$hours'); return _list(r, ['findings']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> dpiAiInspect({String context = ''}) async {
    try { return await _po('/api/dpi/ai-inspect', {'context': context}); } catch (e) { return {'error': e.toString()}; }
  }

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
  Future<Map<String,dynamic>?> aiLogQuery(String question, {String language = 'kql'}) async {
    try { return await _po('/api/logs/ai-query', {'question': question, 'language': language}); } catch (e) { return {'error': e.toString()}; }
  }
  Future<Map<String,dynamic>?> aiLogExplain(String query, int hitCount, List<String> samples) async {
    try { return await _po('/api/logs/ai-explain', {'query': query, 'hit_count': hitCount, 'samples': samples}); } catch (e) { return {'error': e.toString()}; }
  }
  Future<Map<String,dynamic>?> buildDetection(String type, String query, String name, List<String> samples) async {
    try { return await _po('/api/logs/build-detection', {'type': type, 'query': query, 'name': name, 'samples': samples}); } catch (e) { return {'error': e.toString()}; }
  }

  // ── Elastic (ES Query) ───────────────────────────────────────────────────
  // Every method here degrades gracefully when ELASTICSEARCH_URL isn't set:
  // the backend answers 503 (or, for health, a 200 {enabled:false}), which
  // _g/_po turn into a thrown ApiException that these catch into an empty
  // list / null — never a crash.
  Future<Map<String,dynamic>?> esHealth() async { try { return await _g('/api/elastic/health') as Map<String,dynamic>; } catch (_) { return null; } }
  Future<List> esIndices() async { try { final r = await _g('/api/elastic/indices'); return _list(r, ['indices']); } catch (_) { return []; } }
  // Surfaces the backend's error message (invalid DSL, ES not configured,
  // etc.) as a {'error': ...} map instead of null so the query screen can
  // show the analyst exactly why the query failed.
  Future<Map<String,dynamic>?> esQuery(String index, Map<String,dynamic> dsl) async {
    try { return await _po('/api/elastic/query', {'index': index, 'dsl': dsl}); } catch (e) { return {'error': e.toString()}; }
  }
  Future<Map<String,dynamic>?> esExplain(String index, Map<String,dynamic> dsl) async {
    try { return await _po('/api/elastic/explain', {'index': index, 'dsl': dsl}); } catch (e) { return {'error': e.toString()}; }
  }

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
  // Migrated to /api/sup/* (sup_rules) — the real system of record the web
  // Suppression page uses; the legacy /api/suppression/rules endpoints
  // still work but write to a separate, disconnected table.
  Future<List> suppressionRules() async { try { final r = await _g('/api/sup/rules'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createSuppressionRule(Map<String,dynamic> b) async { try { await _po('/api/sup/rules', b); return true; } catch (_) { return false; } }
  Future<bool> updateSuppressionStatus(int id, String status) async { try { await _pa('/api/sup/rules/$id', {'status': status}); return true; } catch (_) { return false; } }
  Future<bool> deleteSuppression(int id) async { try { await _d('/api/sup/rules/$id'); return true; } catch (_) { return false; } }

  // ── Cases ─────────────────────────────────────────────────────────────────
  Future<List> cases({String status=''}) async {
    try { final r = await _g('/api/cases${status.isNotEmpty ? "?status=$status" : ""}'); return _list(r, ['cases','data']); } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> caseDetail(int id) async { try { return await _g('/api/cases/$id'); } catch (_) { return null; } }
  Future<bool> createCase(Map<String,dynamic> b) async { try { await _po('/api/cases', b); return true; } catch (_) { return false; } }
  Future<bool> updateCase(int id, Map<String,dynamic> b) async { try { await _pa('/api/cases/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteCase(int id) async { try { await _d('/api/cases/$id'); return true; } catch (_) { return false; } }
  Future<bool> addCaseComment(int id, String body) async { try { await _po('/api/cases/$id/comments', {'content': body}); return true; } catch (_) { return false; } }
  Future<bool> linkAlertToCase(int caseId, int alertId) async { try { await _po('/api/cases/$caseId/alerts', {'alert_id': alertId}); return true; } catch (_) { return false; } }
  Future<List> caseTasks(int id) async { try { final r = await _g('/api/cases/$id/tasks'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createCaseTask(int id, Map<String,dynamic> b) async { try { await _po('/api/cases/$id/tasks', b); return true; } catch (_) { return false; } }
  Future<bool> updateCaseTask(int id, int taskId, Map<String,dynamic> b) async { try { await _pa('/api/cases/$id/tasks/$taskId', b); return true; } catch (_) { return false; } }
  Future<List> caseEvidence(int id) async { try { final r = await _g('/api/cases/$id/evidence'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> addCaseEvidence(int id, Map<String,dynamic> b) async { try { await _po('/api/cases/$id/evidence', b); return true; } catch (_) { return false; } }
  Future<List> caseNotes(int id) async { try { final r = await _g('/api/cases/$id/notes'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> addCaseNote(int id, String content) async { try { await _po('/api/cases/$id/notes', {'content': content}); return true; } catch (_) { return false; } }

  // ── Playbooks ─────────────────────────────────────────────────────────────
  // Migrated to /api/pb/* (pb_playbooks) — the real system of record the
  // web Playbooks page uses. Also fixes a pre-existing bug: triggerPlaybook
  // called the /enable endpoint instead of executing anything, so "Run"
  // never actually ran a playbook, only silently re-enabled it.
  Future<List> playbooks() async { try { final r = await _g('/api/pb/library'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createPlaybook(Map<String,dynamic> b) async { try { await _po('/api/pb/library', b); return true; } catch (_) { return false; } }
  Future<bool> updatePlaybook(int id, Map<String,dynamic> b) async { try { await _pu('/api/playbooks/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deletePlaybook(int id) async { try { await _d('/api/pb/library/$id'); return true; } catch (_) { return false; } }
  Future<bool> enablePlaybook(int id) async { try { await _po('/api/pb/library/$id/publish', {}); return true; } catch (_) { return false; } }
  Future<bool> disablePlaybook(int id) async { try { await _pa('/api/pb/library/$id', {'status': 'archived'}); return true; } catch (_) { return false; } }
  Future<bool> triggerPlaybook(int id, Map<String,dynamic> payload) async { try { await _po('/api/pb/library/$id/execute', {'trigger_type': 'manual', 'variables': payload}); return true; } catch (_) { return false; } }
  Future<List> playbookExecutions() async { try { final r = await _g('/api/pb/executions'); return r is List ? r : []; } catch (_) { return []; } }

  // ── Approvals ─────────────────────────────────────────────────────────────
  // Migrated to /api/aq/* (aq_requests) — the real SOAR approval queue web
  // users work from. The legacy /api/tasks/pending-approval endpoint is a
  // different concept entirely (agent-task approvals, not SOAR change
  // requests) and still works, but isn't what "Approval Queue" means on web.
  Future<List> pendingApprovals() async { try { final r = await _g('/api/aq/queue?status=pending'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> approveTask(int id) async { try { await _po('/api/aq/queue/$id/decision', {'decision': 'approve'}); return true; } catch (_) { return false; } }
  Future<bool> rejectTask(int id, String reason) async { try { await _po('/api/aq/queue/$id/decision', {'decision': 'reject', 'notes': reason}); return true; } catch (_) { return false; } }

  // ── Vulnerabilities ───────────────────────────────────────────────────────
  // Migrated to /api/vq/* (vq_items) — the real system of record the web
  // Vuln Queue page uses. vq_items has no severity/cvss_score field — it's
  // a remediation-workflow item keyed on priority/risk_score, distinct
  // from vm_findings (the raw vulnerability data VulnerabilitiesScreen
  // shows). Lifecycle actions are 'complete'/'block'/'close', not a
  // free-form patch-status string.
  Future<List> vulnQueue() async { try { final r = await _g('/api/vq/queue'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> vqAction(int id, String action) async { try { await _po('/api/vq/items/$id/action', {'action': action}); return true; } catch (_) { return false; } }

  // ── Quarantine ────────────────────────────────────────────────────────────
  // Migrated to /api/qe/* (qe_items) — the real system of record the web
  // Quarantine page uses; legacy /api/quarantine still works but targets a
  // separate, disconnected file-only table.
  Future<List> quarantine() async { try { final r = await _g('/api/qe/queue'); return r is List ? r : []; } catch (_) { return []; } }
  Future<Map<String,dynamic>?> quarantineStats() async { try { return await _g('/api/qe/dashboard'); } catch (_) { return null; } }
  Future<bool> releaseQuarantine(int id) async { try { await _po('/api/qe/items/$id/action', {'action': 'release'}); return true; } catch (_) { return false; } }

  // ── Vulnerabilities (/api/vm/*, vm_findings) ────────────────────────────
  Future<List> vmFindings({String severity = ''}) async {
    try { final r = await _g('/api/vm/inventory${severity.isNotEmpty ? "?severity=$severity" : ""}'); return r is List ? r : []; } catch (_) { return []; }
  }
  Future<bool> vmFindingAction(int id, String action) async { try { await _po('/api/vm/findings/$id/action', {'action': action}); return true; } catch (_) { return false; } }

  // ── Firewall ──────────────────────────────────────────────────────────────
  Future<List> firewallRules({String group=''}) async {
    try { final r = await _g('/api/firewall/rules${group.isNotEmpty ? "?group=$group" : ""}'); return _list(r, ['rules','data']); } catch (_) { return []; }
  }
  Future<List> firewallGroups() async { try { final r = await _g('/api/firewall/groups'); return _list(r, ['groups','data']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> firewallStats() async { try { return await _g('/api/firewall/stats') as Map<String,dynamic>; } catch (_) { return null; } }
  Future<bool> createFirewallRule(Map<String,dynamic> b) async { try { await _po('/api/firewall/rules', b); return true; } catch (_) { return false; } }
  Future<bool> updateFirewallRule(int id, Map<String,dynamic> b) async { try { await _pu('/api/firewall/rules/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteFirewallRule(int id) async { try { await _d('/api/firewall/rules/$id'); return true; } catch (_) { return false; } }
  Future<bool> syncFirewall() async { try { await _po('/api/firewall/sync', {}); return true; } catch (_) { return false; } }

  // ── Firewall Enterprise (zones / NAT / policies / approvals) ───────────────
  Future<List> fweZones() async { try { final r = await _g('/api/fwe/zones'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createFweZone(Map<String,dynamic> b) async { try { await _po('/api/fwe/zones', b); return true; } catch (_) { return false; } }
  Future<List> fweNAT() async { try { final r = await _g('/api/fwe/nat'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createFweNAT(Map<String,dynamic> b) async { try { await _po('/api/fwe/nat', b); return true; } catch (_) { return false; } }
  Future<bool> deleteFweNAT(int id) async { try { await _d('/api/fwe/nat/$id'); return true; } catch (_) { return false; } }
  Future<List> fwePolicies() async { try { final r = await _g('/api/fwe/policies'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createFwePolicy(Map<String,dynamic> b) async { try { await _po('/api/fwe/policies', b); return true; } catch (_) { return false; } }
  Future<bool> updateFwePolicy(int id, Map<String,dynamic> b) async { try { await _pa('/api/fwe/policies/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteFwePolicy(int id) async { try { await _d('/api/fwe/policies/$id'); return true; } catch (_) { return false; } }
  Future<List> fweApprovals({String status = ''}) async {
    try { final r = await _g('/api/fwe/approvals${status.isNotEmpty ? "?status=$status" : ""}'); return r is List ? r : []; } catch (_) { return []; }
  }
  Future<bool> decideFweApproval(int id, String decision, {String note = ''}) async {
    try { await _po('/api/fwe/approvals/$id/decide', {'decision': decision, 'note': note}); return true; } catch (_) { return false; }
  }

  // ── Scheduled Tasks ───────────────────────────────────────────────────────
  // Migrated to /api/ste/* (ste_tasks) — the real system of record the web
  // Scheduled Tasks page uses; legacy /api/scheduler/tasks still works but
  // targets a separate, disconnected table.
  Future<List> scheduledTasks() async { try { final r = await _g('/api/ste/tasks'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> createScheduledTask(Map<String,dynamic> b) async { try { await _po('/api/ste/tasks', b); return true; } catch (_) { return false; } }
  Future<bool> toggleScheduledTask(int id, bool enabled) async { try { await _pa('/api/ste/tasks/$id', {'enabled': enabled}); return true; } catch (_) { return false; } }
  Future<bool> runScheduledTask(int id) async { try { await _po('/api/ste/tasks/$id/run', {}); return true; } catch (_) { return false; } }
  Future<bool> deleteScheduledTask(int id) async { try { await _d('/api/ste/tasks/$id'); return true; } catch (_) { return false; } }

  // ── DFIR ──────────────────────────────────────────────────────────────────
  Future<List> dfirCollections() async { try { final r = await _g('/api/dfir/collections'); return _list(r, ['collections','data']); } catch (_) { return []; } }
  // TriggerForensicCollection (api/dfir.go:25) binds agent_id/label/
  // artifact_types — it never read collection_type/options, so every
  // "start collection" request previously bound to zero artifact types and
  // a blank label regardless of the type the user picked.
  Future<bool> triggerDfir(int agentId, String type) async { try { await _po('/api/dfir/collections', {'agent_id': agentId, 'label': type, 'artifact_types': [type]}); return true; } catch (_) { return false; } }
  Future<List> dfirArtifacts(int id) async { try { final r = await _g('/api/dfir/collections/$id/artifacts'); return _list(r, ['artifacts','data']); } catch (_) { return []; } }

  // ── Scripts ───────────────────────────────────────────────────────────────
  Future<List> scriptTemplates() async { try { final r = await _g('/api/scripts/templates'); return _list(r, ['templates','data']); } catch (_) { return []; } }
  Future<List> scriptHistory() async { try { final r = await _g('/api/scripts/history'); return _list(r, ['history','data']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> runScript(List<int> agentIds, String script, {String label = '', String shell = 'bash'}) async {
    try { return await _po('/api/scripts/run', {'agent_ids': agentIds, 'script': script, 'label': label, 'shell': shell}); } catch (e) { return {'error': e.toString()}; }
  }
  Future<Map<String,dynamic>?> scriptResult(String taskId) async { try { return await _g('/api/scripts/result/$taskId') as Map<String,dynamic>; } catch (_) { return null; } }

  // ── Assets ────────────────────────────────────────────────────────────────
  // Migrated to /api/ace/assets (ace_assets) — the real system of record
  // the web Assets/CMDB page uses. Unlike the legacy /api/assets table,
  // ace_assets has no create/delete endpoint at all — assets arrive via
  // discovery (GET /api/ace/discovery) and only a fixed metadata subset
  // (owner/business_unit/department/criticality/location/tags/status) is
  // editable, matching real CMDB semantics rather than free-form CRUD.
  Future<List> assets() async { try { final r = await _g('/api/ace/assets'); return r is List ? r : []; } catch (_) { return []; } }
  Future<bool> updateAsset(String assetId, Map<String,dynamic> b) async { try { await _pa('/api/ace/assets/$assetId', b); return true; } catch (_) { return false; } }
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
  Future<bool> updateThreatActor(int id, Map<String,dynamic> b) async { try { await _pa('/api/threat-actors/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteThreatActor(int id) async { try { await _d('/api/threat-actors/$id'); return true; } catch (_) { return false; } }

  // ── Compliance/Reports ────────────────────────────────────────────────────
  // Migrated to /api/rpe/* (rpe_reports) — the real system of record the web
  // Reports page uses. rpe treats a "report" as a saved, re-runnable
  // definition (status active/archived + last_generated_at/generation_count)
  // rather than the legacy model's one-shot pending→generating→completed
  // request, so generate is always available, not gated on status.
  Future<List> complianceReports() async { try { final r = await _g('/api/rpe/reports'); return r is List ? r : []; } catch (_) { return []; } }
  Future<List> reports() => complianceReports();
  Future<bool> createReport(Map<String,dynamic> b) async { try { await _po('/api/rpe/reports', b); return true; } catch (_) { return false; } }
  Future<bool> generateReport(String reportId) async { try { await _po('/api/rpe/generate/$reportId', {}); return true; } catch (_) { return false; } }
  Future<bool> deleteReport(int id) async { try { await _d('/api/rpe/reports/$id'); return true; } catch (_) { return false; } }
  // Migrated to /api/fce/frameworks (fce_frameworks) — the real system of
  // record the web Frameworks page uses.
  Future<List> frameworkAssessments() async { try { final r = await _g('/api/fce/frameworks'); return r is List ? r : []; } catch (_) { return []; } }
  Future<List> frameworks() => frameworkAssessments();
  // No framework-compliance refresh endpoint — refresh risk posture as proxy
  Future<bool> refreshFrameworks() async { try { await _po('/api/risk-posture/refresh', {}); return true; } catch (_) { return false; } }
  // Migrated to /api/exe/dashboard (exe_snapshots) — the real system of
  // record the web Executive page uses.
  Future<Map<String,dynamic>?> executiveMetrics() async { try { return await _g('/api/exe/dashboard'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> executiveSummary() => executiveMetrics();
  // Migrated to /api/sme/dashboard (sme_snapshots) — the real system of
  // record the web SOC Metrics page uses. Unwrapped here (response nests
  // the flat metrics under "latest") so existing callers reading top-level
  // keys don't need to know about the wrapper.
  Future<Map<String,dynamic>?> socMetrics() async {
    try {
      final r = await _g('/api/sme/dashboard');
      return (r is Map ? r['latest'] : null) as Map<String,dynamic>?;
    } catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> socAlertMetrics() async { try { return await _g('/api/sme/alerts'); } catch (_) { return null; } }
  Future<List> socAnalysts() async { try { final r = await _g('/api/sme/analysts'); return _list(r, ['analysts']); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> riskPosture() async { try { return await _g('/api/risk-posture'); } catch (_) { return null; } }
  Future<bool> refreshRiskPosture() async { try { await _po('/api/risk-posture/refresh', {}); return true; } catch (_) { return false; } }

  // ── AI ────────────────────────────────────────────────────────────────────
  // AIChatHandler (api/ai.go:130) is stateless per-request — it takes the
  // full prior turn history in the body and returns the updated history in
  // the response; there is no session_id/context field anywhere. Previously
  // sent an empty 'context' string and a 'session_id' the handler never
  // read, and never sent 'history' at all — every message was answered with
  // zero memory of earlier turns in the same conversation.
  Future<Map<String,dynamic>?> aiChat(String message, List<Map<String,dynamic>> history) async {
    try {
      return await _po('/api/ai/chat', {'message': message, 'history': history});
    } catch (_) { return null; }
  }
  Future<List> chatHistory() async { try { final r = await _g('/api/ai/chat/history'); return _list(r, ['messages','history','data']); } catch (_) { return []; } }
  Future<bool> clearChatHistory() async { try { await _d('/api/ai/chat/history'); return true; } catch (_) { return false; } }
  Future<bool> triageAlert(int id) async { try { await _po('/api/ai/triage/$id', {}); return true; } catch (_) { return false; } }

  // ── AI Assistant Enterprise (recommendations + prompt library) ─────────────
  Future<List> aiaRecommendations() async { try { final r = await _g('/api/aia/recommendations'); return _list(r, ['recommendations','data']); } catch (_) { return []; } }
  Future<bool> updateAiaRecommendation(String recId, String status) async { try { await _pa('/api/aia/recommendations/$recId', {'status': status}); return true; } catch (_) { return false; } }
  Future<List> aiaPrompts() async { try { final r = await _g('/api/aia/prompts'); return _list(r, ['prompts','data']); } catch (_) { return []; } }
  Future<bool> createAiaPrompt(Map<String,dynamic> b) async { try { await _po('/api/aia/prompts', b); return true; } catch (_) { return false; } }

  // ── Settings ──────────────────────────────────────────────────────────────
  Future<List> users() async { try { final r = await _g('/api/users'); return _list(r, ['users','data']); } catch (_) { return []; } }
  // No POST /api/users route exists — user creation goes through the real
  // invite flow below (email a reset-password link) instead.
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

  // ── Security Policy & Sessions ──────────────────────────────────────────
  Future<Map<String,dynamic>?> securityPolicy() async { try { return await _g('/api/security-policy'); } catch (_) { return null; } }
  Future<bool> updateSecurityPolicy(Map<String,dynamic> b) async { try { await _pu('/api/security-policy', b); return true; } catch (_) { return false; } }
  Future<List> allSessions() async { try { final r = await _g('/api/sessions'); return _list(r, ['sessions']); } catch (_) { return []; } }
  Future<bool> revokeSession(int id) async { try { await _d('/api/sessions/$id'); return true; } catch (_) { return false; } }

  // ── System Settings (/api/stte/*) ───────────────────────────────────────
  Future<Map<String,dynamic>?> stteOrg() async { try { return await _g('/api/stte/org'); } catch (_) { return null; } }
  Future<bool> updateStteOrg(Map<String,dynamic> b) async { try { await _pa('/api/stte/org', b); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> stteBackups() async { try { return await _g('/api/stte/backups'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> triggerBackup() async { try { return await _po('/api/stte/backups/trigger', {}); } catch (e) { return {'error': e.toString()}; } }
  Future<bool> updateBackupConfig(Map<String,dynamic> b) async { try { await _pa('/api/stte/backups/config', b); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> stteUpdates() async { try { return await _g('/api/stte/updates'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> checkUpdates() async { try { return await _po('/api/stte/updates/check', {}); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> stteLicense() async { try { return await _g('/api/stte/license'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> activateLicense(String key) async { try { return await _po('/api/stte/license/activate', {'license_key': key}); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> stteAgentsConfig() async { try { return await _g('/api/stte/agents-config'); } catch (_) { return null; } }
  Future<bool> updateStteAgentsConfig(Map<String,dynamic> b) async { try { await _pa('/api/stte/agents-config', b); return true; } catch (_) { return false; } }
  Future<List> stteAudit() async { try { final r = await _g('/api/stte/audit'); return r is List ? r : []; } catch (_) { return []; } }
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

  // ── Cloud Security (api/cloud_security_enterprise.go) ─────────────────────
  // Previously this whole category (and 7 siblings under Cloud & Infra) was
  // backed by a single generic ItdrScreen filtering /api/itdr/findings?type=
  // <category> — but itdr_findings.finding_type only ever holds values like
  // brute_force/credential_theft/mfa_gap, never "cloud"/"ad"/"email", so that
  // filter matched zero rows for every one of these 8 tabs, always. Each
  // category has its own real, much richer backend (this one: /api/cloud/*)
  // that was never wired to any mobile screen at all.
  Future<Map<String,dynamic>?> cloudDashboard() async { try { return await _g('/api/cloud/dashboard'); } catch (_) { return null; } }
  Future<List> cloudAccounts() async { try { final r = await _g('/api/cloud/accounts'); return _list(r, []); } catch (_) { return []; } }
  Future<bool> createCloudAccount(Map<String,dynamic> b) async { try { await _po('/api/cloud/accounts', b); return true; } catch (_) { return false; } }
  Future<bool> deleteCloudAccount(int id) async { try { await _d('/api/cloud/accounts/$id'); return true; } catch (_) { return false; } }
  Future<List> cloudInventory({String provider='', String resourceType=''}) async {
    try {
      final qs = <String,String>{};
      if (provider.isNotEmpty) qs['provider'] = provider;
      if (resourceType.isNotEmpty) qs['resource_type'] = resourceType;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/cloud/inventory$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> cloudCSPMFindings({String category='', String severity=''}) async {
    try {
      final qs = <String,String>{};
      if (category.isNotEmpty) qs['category'] = category;
      if (severity.isNotEmpty) qs['severity'] = severity;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/cloud/cspm/findings$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> cloudCSPMSummary() async { try { final r = await _g('/api/cloud/cspm/summary'); return _list(r, []); } catch (_) { return []; } }
  Future<bool> patchCloudFinding(int id, String status) async { try { await _pa('/api/cloud/cspm/findings/$id', {'status': status}); return true; } catch (_) { return false; } }
  Future<List> cloudIdentities({String type='', String riskLevel=''}) async {
    try {
      final qs = <String,String>{};
      if (type.isNotEmpty) qs['type'] = type;
      if (riskLevel.isNotEmpty) qs['risk_level'] = riskLevel;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/cloud/ciem/identities$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> cloudCIEMRisks() async { try { return await _g('/api/cloud/ciem/risks'); } catch (_) { return null; } }
  Future<List> cloudThreats({String threatType='', String provider=''}) async {
    try {
      final qs = <String,String>{};
      if (threatType.isNotEmpty) qs['threat_type'] = threatType;
      if (provider.isNotEmpty) qs['provider'] = provider;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/cloud/threats$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> cloudExposure() async { try { return await _g('/api/cloud/exposure'); } catch (_) { return null; } }
  Future<List> cloudCompliance() async { try { final r = await _g('/api/cloud/compliance'); return _list(r, []); } catch (_) { return []; } }
  Future<List> cloudTimeline() async { try { final r = await _g('/api/cloud/timeline'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> cloudAttackPaths() async { try { return await _g('/api/cloud/attack-paths'); } catch (_) { return null; } }
  Future<List> cloudDrift() async { try { final r = await _g('/api/cloud/drift'); return _list(r, []); } catch (_) { return []; } }
  Future<bool> ackCloudDrift(int id) async { try { await _pa('/api/cloud/drift/$id', {}); return true; } catch (_) { return false; } }
  Future<List> cloudVulnerabilities() async { try { final r = await _g('/api/cloud/vulnerabilities'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> cloudThreatIntel() async { try { return await _g('/api/cloud/threat-intel'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> cloudAnalytics() async { try { return await _g('/api/cloud/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> cloudAI(String question, {String mode='', String resourceId='', int findingId=0}) async {
    try { return await _po('/api/cloud/ai', {'question': question, 'mode': mode, 'resource_id': resourceId, 'finding_id': findingId}); }
    catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> cloudRespond(Map<String,dynamic> body) async { try { return await _po('/api/cloud/response', body); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> cloudReport(String reportType) async { try { return await _po('/api/cloud/report', {'report_type': reportType}); } catch (_) { return null; } }

  // ── Email Security (api/email_security_enterprise.go) ─────────────────────
  // This nav item ("Cloud & Infra" group) was backed by the shared ItdrScreen
  // filtering /api/itdr/findings?type=email — but itdr_findings.finding_type
  // only ever holds values like brute_force/credential_theft/mfa_gap, never
  // "email", so that filter always matched zero rows. The real backend at
  // /api/email/* is a much richer mail-flow/threat/campaign/policy system
  // that had never been wired to any mobile screen at all.
  Future<Map<String,dynamic>?> emailDashboard() async { try { return await _g('/api/email/dashboard'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> emailMailFlow() async { try { return await _g('/api/email/mail-flow'); } catch (_) { return null; } }
  Future<List> emailMessages({String search='', String sender='', String recipient='', String subject='', String status='', String threatType='', String messageId=''}) async {
    try {
      final qs = <String,String>{};
      if (search.isNotEmpty) qs['q'] = search;
      if (sender.isNotEmpty) qs['sender'] = sender;
      if (recipient.isNotEmpty) qs['recipient'] = recipient;
      if (subject.isNotEmpty) qs['subject'] = subject;
      if (status.isNotEmpty) qs['status'] = status;
      if (threatType.isNotEmpty) qs['threat_type'] = threatType;
      if (messageId.isNotEmpty) qs['message_id'] = messageId;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/email/messages$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> emailThreats({String type=''}) async {
    try {
      final r = await _g('/api/email/threats${type.isNotEmpty ? "?type=$type" : ""}');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> emailAttachments({String verdict='', String fileType=''}) async {
    try {
      final qs = <String,String>{};
      if (verdict.isNotEmpty) qs['verdict'] = verdict;
      if (fileType.isNotEmpty) qs['file_type'] = fileType;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/email/attachments$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> emailUrls({String verdict=''}) async {
    try {
      final r = await _g('/api/email/urls${verdict.isNotEmpty ? "?verdict=$verdict" : ""}');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> emailAuthResults() async { try { return await _g('/api/email/auth-results'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> emailSenderIntel({String domain='', String email=''}) async {
    try {
      final qs = <String,String>{};
      if (domain.isNotEmpty) qs['domain'] = domain;
      if (email.isNotEmpty) qs['email'] = email;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      return await _g('/api/email/sender-intel$q');
    } catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> emailThreatIntel() async { try { return await _g('/api/email/threat-intel'); } catch (_) { return null; } }
  Future<List> emailCampaigns() async { try { final r = await _g('/api/email/campaigns'); return _list(r, []); } catch (_) { return []; } }
  Future<List> emailTimeline() async { try { final r = await _g('/api/email/timeline'); return _list(r, []); } catch (_) { return []; } }
  Future<List> emailUserRisk() async { try { final r = await _g('/api/email/user-risk'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> emailAnalytics() async { try { return await _g('/api/email/analytics'); } catch (_) { return null; } }
  Future<List> emailPolicies() async { try { final r = await _g('/api/email/policies'); return _list(r, []); } catch (_) { return []; } }
  Future<bool> createEmailPolicy(Map<String,dynamic> b) async { try { await _po('/api/email/policies', b); return true; } catch (_) { return false; } }
  Future<bool> updateEmailPolicy(int id, Map<String,dynamic> b) async { try { await _pa('/api/email/policies/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteEmailPolicy(int id) async { try { await _d('/api/email/policies/$id'); return true; } catch (_) { return false; } }
  Future<List> emailReported() async { try { final r = await _g('/api/email/reported'); return _list(r, []); } catch (_) { return []; } }
  Future<bool> patchEmailReported(int id, {String? triageStatus, String? analystNotes}) async {
    try {
      final body = <String,dynamic>{};
      if (triageStatus != null) body['triage_status'] = triageStatus;
      if (analystNotes != null) body['analyst_notes'] = analystNotes;
      await _pa('/api/email/reported/$id', body);
      return true;
    } catch (_) { return false; }
  }
  Future<Map<String,dynamic>?> emailRespond(Map<String,dynamic> body) async { try { return await _po('/api/email/response', body); } catch (e) { return {'error': e.toString()}; } }

  // ── Container Security (api/container_security_enterprise.go) ─────────────
  // This was one of 8 "Cloud & Infra" nav tabs sharing a single generic
  // ItdrScreen filtering /api/itdr/findings?type=container — but that
  // column never actually holds "container" as a value (only things like
  // brute_force/credential_theft/mfa_gap), so it always returned zero rows.
  // The real backend lives entirely under /api/containers/*, keyed on
  // k8s_clusters/k8s_nodes/k8s_pods/k8s_images/k8s_runtime_alerts/
  // k8s_rbac_findings/k8s_network_policies/k8s_admission_violations, and was
  // never wired to any mobile screen at all.
  Future<Map<String,dynamic>?> containerDashboard() async { try { return await _g('/api/containers/dashboard'); } catch (_) { return null; } }
  Future<List> containerClusters() async { try { final r = await _g('/api/containers/clusters'); return _list(r, []); } catch (_) { return []; } }
  Future<List> containerNodes({String clusterId=''}) async {
    try {
      final q = clusterId.isNotEmpty ? '?cluster_id=$clusterId' : '';
      final r = await _g('/api/containers/nodes$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> containerNamespaces() async { try { final r = await _g('/api/containers/namespaces'); return _list(r, []); } catch (_) { return []; } }
  Future<List> containerPods({String namespace='', bool privilegedOnly=false, String clusterId=''}) async {
    try {
      final qs = <String,String>{};
      if (namespace.isNotEmpty) qs['namespace'] = namespace;
      if (privilegedOnly) qs['privileged'] = 'true';
      if (clusterId.isNotEmpty) qs['cluster_id'] = clusterId;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/containers/pods$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> containerImages({String registry=''}) async {
    try {
      final q = registry.isNotEmpty ? '?registry=$registry' : '';
      final r = await _g('/api/containers/images$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> containerSupplyChain() async { try { return await _g('/api/containers/supply-chain'); } catch (_) { return null; } }
  Future<List> containerRuntimeAlerts({String severity='', String alertType=''}) async {
    try {
      final qs = <String,String>{};
      if (severity.isNotEmpty) qs['severity'] = severity;
      if (alertType.isNotEmpty) qs['alert_type'] = alertType;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/containers/runtime-alerts$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  // GetK8sRBAC returns an object {findings, total, cluster_roles, bindings,
  // excessive, wildcard} — not a bare array.
  Future<Map<String,dynamic>?> containerRBAC() async { try { return await _g('/api/containers/rbac'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> containerSecrets() async { try { return await _g('/api/containers/secrets'); } catch (_) { return null; } }
  Future<List> containerNetworkPolicies() async { try { final r = await _g('/api/containers/network-policies'); return _list(r, []); } catch (_) { return []; } }
  Future<List> containerAdmission() async { try { final r = await _g('/api/containers/admission'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> containerCompliance() async { try { return await _g('/api/containers/compliance'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> containerThreatIntel() async { try { return await _g('/api/containers/threat-intel'); } catch (_) { return null; } }
  Future<List> containerTimeline({int limit=50}) async { try { final r = await _g('/api/containers/timeline?limit=$limit'); return _list(r, []); } catch (_) { return []; } }
  Future<List> containerVulnerabilities() async { try { final r = await _g('/api/containers/vulnerabilities'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> containerAttackPaths() async { try { return await _g('/api/containers/attack-paths'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> containerAnalytics() async { try { return await _g('/api/containers/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> containerRespond(Map<String,dynamic> body) async { try { return await _po('/api/containers/response', body); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> containerReport(String reportType) async { try { return await _po('/api/containers/report', {'report_type': reportType}); } catch (_) { return null; } }

  // ── AD Security (api/ad_security_enterprise.go) ────────────────────────────
  // This "AD Attacks" tab used to run through the shared ItdrScreen, filtered
  // on /api/itdr/findings?type=ad — but itdr_findings.finding_type only ever
  // holds values like brute_force/credential_theft/mfa_gap, never literally
  // "ad", so it always returned zero rows. The real backend at /api/ad/* is
  // much richer (dashboard/inventory/identity-risk/auth-monitor/attacks/
  // gpo-changes/changes/attack-paths/tiering/exposure/threat-intel/timeline/
  // graph/analytics/assessment) and was never wired to mobile at all.
  Future<Map<String,dynamic>?> adDashboard() async { try { return await _g('/api/ad/dashboard'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adInventory() async { try { return await _g('/api/ad/inventory'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adIdentityRisk({String filter=''}) async {
    try {
      final qs = <String,String>{};
      if (filter.isNotEmpty) qs['filter'] = filter;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      return await _g('/api/ad/identity-risk$q');
    } catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> adAuthMonitor() async { try { return await _g('/api/ad/auth-monitor'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adAttacks({String category='', String attackType=''}) async {
    try {
      final qs = <String,String>{};
      if (category.isNotEmpty) qs['category'] = category;
      if (attackType.isNotEmpty) qs['attack_type'] = attackType;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      return await _g('/api/ad/attacks$q');
    } catch (_) { return null; }
  }
  Future<List> adGPOChanges() async { try { final r = await _g('/api/ad/gpo-changes'); return _list(r, []); } catch (_) { return []; } }
  Future<List> adChanges() async { try { final r = await _g('/api/ad/changes'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> adAttackPaths() async { try { return await _g('/api/ad/attack-paths'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adTiering() async { try { return await _g('/api/ad/tiering'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adExposure() async { try { return await _g('/api/ad/exposure'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adThreatIntel() async { try { return await _g('/api/ad/threat-intel'); } catch (_) { return null; } }
  Future<List> adTimeline() async { try { final r = await _g('/api/ad/timeline'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> adGraph() async { try { return await _g('/api/ad/graph'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adAnalytics() async { try { return await _g('/api/ad/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adAssessment() async { try { return await _g('/api/ad/assessment'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> adRespond(Map<String,dynamic> body) async { try { return await _po('/api/ad/response', body); } catch (e) { return {'error': e.toString()}; } }

  // ── OT/ICS (api/ot_ics_enterprise.go) ──────────────────────────────────────
  // Same bug as every other Cloud & Infra tab: this whole category rode on
  // the generic ItdrScreen filtering /api/itdr/findings?type=ot_ics — a value
  // that column never actually holds (only brute_force/credential_theft/
  // mfa_gap etc.) — so it always returned zero rows. Real backend: /api/ot/*.
  Future<Map<String,dynamic>?> otDashboard() async { try { return await _g('/api/ot/dashboard'); } catch (_) { return null; } }
  Future<List> otAssets({String type='', String zone='', String site=''}) async {
    try {
      final qs = <String,String>{};
      if (type.isNotEmpty) qs['type'] = type;
      if (zone.isNotEmpty) qs['zone'] = zone;
      if (site.isNotEmpty) qs['site'] = site;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/ot/assets$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> otTopology() async { try { return await _g('/api/ot/topology'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otProtocols() async { try { return await _g('/api/ot/protocols'); } catch (_) { return null; } }
  Future<List> otTraffic({String protocol='', bool unauthorizedOnly=false}) async {
    try {
      final qs = <String,String>{};
      if (protocol.isNotEmpty) qs['protocol'] = protocol;
      if (unauthorizedOnly) qs['unauthorized'] = 'true';
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/ot/traffic$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> otAlerts({String severity=''}) async {
    try { return await _g('/api/ot/alerts${severity.isNotEmpty ? "?severity=$severity" : ""}'); } catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> otDevices() async { try { return await _g('/api/ot/devices'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otThreats() async { try { return await _g('/api/ot/threats'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otDPI() async { try { return await _g('/api/ot/dpi'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otRisk() async { try { return await _g('/api/ot/risk'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otVulnerabilities() async { try { return await _g('/api/ot/vulnerabilities'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otZones() async { try { return await _g('/api/ot/zones'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otBaseline() async { try { return await _g('/api/ot/baseline'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otThreatIntel() async { try { return await _g('/api/ot/threat-intel'); } catch (_) { return null; } }
  Future<List> otTimeline() async { try { final r = await _g('/api/ot/timeline'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> otCompliance() async { try { return await _g('/api/ot/compliance'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otAttackPaths() async { try { return await _g('/api/ot/attack-paths'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otAnalytics() async { try { return await _g('/api/ot/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> otRespond(Map<String,dynamic> body) async { try { return await _po('/api/ot/response', body); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> otReport(String reportType) async { try { return await _po('/api/ot/report', {'report_type': reportType}); } catch (_) { return null; } }

  // ── Supply Chain (api/supply_chain_enterprise.go) ──────────────────────────
  // One of the 8 "Cloud & Infra" tabs previously backed by the shared generic
  // ItdrScreen filtering /api/itdr/findings?type=supply_chain — that column
  // only ever holds values like brute_force/credential_theft/mfa_gap, never
  // "supply_chain", so it always returned zero rows. Real backend below.
  Future<Map<String,dynamic>?> supplyChainDashboard() async { try { return await _g('/api/supply-chain/dashboard'); } catch (_) { return null; } }
  Future<List> supplyChainRepositories() async { try { final r = await _g('/api/supply-chain/repositories'); return _list(r, []); } catch (_) { return []; } }
  Future<List> supplyChainDependencies({String ecosystem='', bool hasCves=false}) async {
    try {
      final qs = <String,String>{};
      if (ecosystem.isNotEmpty) qs['ecosystem'] = ecosystem;
      if (hasCves) qs['has_cves'] = 'true';
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/supply-chain/dependencies$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> supplyChainVulnerabilities({String severity='', bool kev=false}) async {
    try {
      final qs = <String,String>{};
      if (severity.isNotEmpty) qs['severity'] = severity;
      if (kev) qs['kev'] = 'true';
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      return await _g('/api/supply-chain/vulnerabilities$q');
    } catch (_) { return null; }
  }
  Future<List> supplyChainSBOMs() async { try { final r = await _g('/api/supply-chain/sboms'); return _list(r, []); } catch (_) { return []; } }
  Future<List> supplyChainPipelines() async { try { final r = await _g('/api/supply-chain/pipelines'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> supplyChainSecrets() async { try { return await _g('/api/supply-chain/secrets'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> supplyChainCodeIntegrity() async { try { return await _g('/api/supply-chain/code-integrity'); } catch (_) { return null; } }
  Future<List> supplyChainArtifacts() async { try { final r = await _g('/api/supply-chain/artifacts'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> supplyChainThirdParty() async { try { return await _g('/api/supply-chain/third-party'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> supplyChainProvenance() async { try { return await _g('/api/supply-chain/provenance'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> supplyChainThreatIntel() async { try { return await _g('/api/supply-chain/threat-intel'); } catch (_) { return null; } }
  Future<List> supplyChainTimeline() async { try { final r = await _g('/api/supply-chain/timeline'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> supplyChainAnalytics() async { try { return await _g('/api/supply-chain/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> supplyChainCompliance() async { try { return await _g('/api/supply-chain/compliance'); } catch (_) { return null; } }
  Future<List> supplyChainPolicies() async { try { final r = await _g('/api/supply-chain/policies'); return _list(r, []); } catch (_) { return []; } }
  Future<bool> createSupplyChainPolicy(Map<String,dynamic> b) async { try { await _po('/api/supply-chain/policies', b); return true; } catch (_) { return false; } }
  Future<bool> patchSupplyChainPolicy(int id, Map<String,dynamic> b) async { try { await _pa('/api/supply-chain/policies/$id', b); return true; } catch (_) { return false; } }
  Future<bool> deleteSupplyChainPolicy(int id) async { try { await _d('/api/supply-chain/policies/$id'); return true; } catch (_) { return false; } }
  Future<Map<String,dynamic>?> supplyChainRespond(Map<String,dynamic> body) async { try { return await _po('/api/supply-chain/response', body); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> supplyChainReport(String reportType) async { try { return await _po('/api/supply-chain/report', {'report_type': reportType}); } catch (_) { return null; } }

  // ── Process Injection (api/process_injection_enterprise.go) ────────────────
  // Nav id 14 ("Process Injection") was one of 8 "Cloud & Infra" tabs sharing
  // ItdrScreen's /api/itdr/findings?type=process_inject filter — finding_type
  // never actually holds that literal value, so it always returned zero
  // rows. This wires the real, dedicated /api/pi/* backend instead.
  Future<Map<String,dynamic>?> piDashboard() async { try { return await _g('/api/pi/dashboard'); } catch (_) { return null; } }
  Future<List> piProcesses({String hostname='', bool suspiciousOnly=false}) async {
    try {
      final qs = <String,String>{};
      if (hostname.isNotEmpty) qs['hostname'] = hostname;
      if (suspiciousOnly) qs['suspicious'] = 'true';
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/pi/processes$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<List> piProcessTree({String hostname=''}) async {
    try {
      final q = hostname.isEmpty ? '' : '?${Uri(queryParameters: {'hostname': hostname}).query}';
      final r = await _g('/api/pi/process-tree$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> piInjections({String technique='', String severity=''}) async {
    try {
      final qs = <String,String>{};
      if (technique.isNotEmpty) qs['technique'] = technique;
      if (severity.isNotEmpty) qs['severity'] = severity;
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      return await _g('/api/pi/injections$q');
    } catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> piMemory() async { try { return await _g('/api/pi/memory'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piModules() async { try { return await _g('/api/pi/modules'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piHandles() async { try { return await _g('/api/pi/handles'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piApiCalls() async { try { return await _g('/api/pi/api-calls'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piBehavioral() async { try { return await _g('/api/pi/behavioral'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piThreatIntel() async { try { return await _g('/api/pi/threat-intel'); } catch (_) { return null; } }
  Future<List> piTimeline() async { try { final r = await _g('/api/pi/timeline'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> piMitreMap() async { try { return await _g('/api/pi/mitre'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piAnalytics() async { try { return await _g('/api/pi/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> piRespond(Map<String,dynamic> body) async { try { return await _po('/api/pi/response', body); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> piReport(String reportType) async { try { return await _po('/api/pi/report', {'report_type': reportType}); } catch (_) { return null; } }

  // ── Defense Evasion (api/defense_evasion_enterprise.go) ────────────────────
  // Nav id 15 ("Defense Evasion") was one of 8 "Cloud & Infra" tabs sharing
  // ItdrScreen's /api/itdr/findings?type=defense_evasion filter —
  // finding_type never actually holds that literal value, so it always
  // returned zero rows. This wires the real, dedicated /api/de/* backend.
  Future<Map<String,dynamic>?> deDashboard() async { try { return await _g('/api/de/dashboard'); } catch (_) { return null; } }
  // controls/tamper respond with a wrapped object ({controls|events, plus
  // counts}), so these stay on the Map-returning _g — the screen reads both
  // the list and the counts back out of the same response.
  Future<Map<String,dynamic>?> deControls({int limit=0}) async {
    try { return await _g('/api/de/controls${limit>0 ? '?limit=$limit' : ''}'); } catch (_) { return null; }
  }
  Future<Map<String,dynamic>?> deTamper({int limit=0}) async {
    try { return await _g('/api/de/tamper${limit>0 ? '?limit=$limit' : ''}'); } catch (_) { return null; }
  }
  Future<List> deLogEvasion({int limit=0}) async {
    try { final r = await _g('/api/de/log-evasion${limit>0 ? '?limit=$limit' : ''}'); return _list(r, []); } catch (_) { return []; }
  }
  Future<List> deEvasionEvents({String category='', int limit=0}) async {
    try {
      final qs = <String,String>{};
      if (category.isNotEmpty) qs['category'] = category;
      if (limit>0) qs['limit'] = '$limit';
      final q = qs.isEmpty ? '' : '?${Uri(queryParameters: qs).query}';
      final r = await _g('/api/de/evasion-events$q');
      return _list(r, []);
    } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> deBehavioral() async { try { return await _g('/api/de/behavioral'); } catch (_) { return null; } }
  Future<List> deCorrelation() async { try { final r = await _g('/api/de/correlation'); return _list(r, []); } catch (_) { return []; } }
  Future<Map<String,dynamic>?> deMITRE() async { try { return await _g('/api/de/mitre'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> deThreatIntel() async { try { return await _g('/api/de/threat-intel'); } catch (_) { return null; } }
  Future<List> deTimeline({int limit=0}) async {
    try { final r = await _g('/api/de/timeline${limit>0 ? '?limit=$limit' : ''}'); return _list(r, []); } catch (_) { return []; }
  }
  Future<Map<String,dynamic>?> deAnalytics() async { try { return await _g('/api/de/analytics'); } catch (_) { return null; } }
  Future<Map<String,dynamic>?> deRespond(Map<String,dynamic> body) async { try { return await _po('/api/de/response', body); } catch (e) { return {'error': e.toString()}; } }
  Future<Map<String,dynamic>?> deReport(String reportType) async { try { return await _po('/api/de/report', {'report_type': reportType}); } catch (_) { return null; } }
}
