import 'api_client.dart';
import 'secure_storage.dart';

// Admin API client — uses an API key (Bearer token) to access every NGFW
// dashboard endpoint. Only available when the user stored an API key during
// enrollment. All methods swallow errors and return safe defaults so callers
// don't need try/catch.

class DashboardApi {
  static Future<DashboardApi?> create() async {
    final url    = await SecureStore.serverUrl();
    final apiKey = await SecureStore.apiKey();
    if (url == null || url.isEmpty || apiKey == null || apiKey.isEmpty) return null;
    return DashboardApi._(ApiClient(baseUrl: url, agentToken: apiKey));
  }

  DashboardApi._(this._c);
  final ApiClient _c;

  // ── Dashboard ─────────────────────────────────────────────────────────────

  Future<Map<String, dynamic>?> getOverview() async {
    try { return await _c.get('/api/dashboard/overview'); }
    catch (_) { return null; }
  }

  // ── Alerts ────────────────────────────────────────────────────────────────

  Future<List<dynamic>> getAlerts({int page = 1, int perPage = 30, String severity = '', String status = ''}) async {
    try {
      final params = <String, String>{'page': '$page', 'per_page': '$perPage'};
      if (severity.isNotEmpty) params['severity'] = severity;
      if (status.isNotEmpty)   params['status']   = status;
      final q = params.entries.map((e) => '${e.key}=${e.value}').join('&');
      final r = await _c.get('/api/alerts/paginated?$q');
      return (r['alerts'] as List?) ?? [];
    } catch (_) { return []; }
  }

  Future<bool> acknowledgeAlert(int id, {String note = ''}) async {
    try { await _c.post('/api/alerts/$id/acknowledge', {'note': note}); return true; }
    catch (_) { return false; }
  }

  Future<bool> resolveAlert(int id, {String note = ''}) async {
    try { await _c.post('/api/alerts/$id/resolve', {'note': note}); return true; }
    catch (_) { return false; }
  }

  // ── Incidents ─────────────────────────────────────────────────────────────

  Future<List<dynamic>> getIncidents({int page = 1, int perPage = 20, String status = ''}) async {
    try {
      final q = 'page=$page&per_page=$perPage${status.isNotEmpty ? "&status=$status" : ""}';
      final r = await _c.get('/api/incidents/paginated?$q');
      return (r['incidents'] as List?) ?? [];
    } catch (_) { return []; }
  }

  Future<bool> updateIncidentStatus(int id, String status) async {
    try { await _c.put('/api/incidents/$id/status', {'status': status}); return true; }
    catch (_) { return false; }
  }

  Future<bool> addIncidentNote(int id, String note) async {
    try { await _c.post('/api/incidents/$id/notes', {'note': note}); return true; }
    catch (_) { return false; }
  }

  // ── Agents ────────────────────────────────────────────────────────────────

  Future<List<dynamic>> getAgents() async {
    try {
      final r = await _c.get('/api/agents');
      if (r['data'] is List)   return r['data'] as List;
      if (r['agents'] is List) return r['agents'] as List;
      if (r.values.isNotEmpty && r.values.first is List) return r.values.first as List;
      return [];
    } catch (_) { return []; }
  }

  Future<bool> queueAgentTask(int agentId, String taskType, {Map<String, dynamic>? payload}) async {
    try {
      await _c.post('/api/tasks', {
        'agent_id': agentId,
        'task_type': taskType,
        'payload': payload ?? {},
      });
      return true;
    } catch (_) { return false; }
  }

  // ── Cases ─────────────────────────────────────────────────────────────────

  Future<List<dynamic>> getCases({String status = ''}) async {
    try {
      final q = status.isNotEmpty ? '?status=$status' : '';
      final r = await _c.get('/api/cases$q');
      if (r['cases'] is List) return r['cases'] as List;
      if (r['data']  is List) return r['data']  as List;
      return [];
    } catch (_) { return []; }
  }

  Future<bool> createCase(String title, String description, String severity) async {
    try {
      await _c.post('/api/cases', {'title': title, 'description': description, 'severity': severity});
      return true;
    } catch (_) { return false; }
  }

  Future<bool> updateCaseStatus(int id, String status) async {
    try { await _c.put('/api/cases/$id', {'status': status}); return true; }
    catch (_) { return false; }
  }

  Future<bool> addCaseComment(int id, String body) async {
    try { await _c.post('/api/cases/$id/comments', {'body': body}); return true; }
    catch (_) { return false; }
  }

  // ��─ SOAR approvals ────────────────────────────────────────────────────────

  Future<List<dynamic>> getPendingApprovals() async {
    try {
      final r = await _c.get('/api/tasks/pending-approval');
      if (r['data'] is List) return r['data'] as List;
      return [];
    } catch (_) { return []; }
  }

  Future<bool> approveTask(int id) async {
    try { await _c.post('/api/tasks/$id/approve', {}); return true; }
    catch (_) { return false; }
  }

  Future<bool> rejectTask(int id, String reason) async {
    try { await _c.post('/api/tasks/$id/reject', {'reason': reason}); return true; }
    catch (_) { return false; }
  }

  // ── Firewall ──────────────────────────────────────────────────────────────

  Future<List<dynamic>> getFirewallRules({String group = ''}) async {
    try {
      final q = group.isNotEmpty ? '?group=$group' : '';
      final r = await _c.get('/api/firewall/rules$q');
      if (r['rules'] is List) return r['rules'] as List;
      if (r['data']  is List) return r['data']  as List;
      return [];
    } catch (_) { return []; }
  }

  Future<bool> deleteFirewallRule(int id) async {
    try { await _c.delete('/api/firewall/rules/$id'); return true; }
    catch (_) { return false; }
  }

  // ── Playbooks ─────────────────────────────────────────────────────────────

  Future<List<dynamic>> getPlaybooks() async {
    try {
      final r = await _c.get('/api/playbooks');
      if (r['data'] is List) return r['data'] as List;
      return [];
    } catch (_) { return []; }
  }

  // ── MDM Devices ───────────────────────────────────────────────────────────

  Future<List<dynamic>> getMDMDevices() async {
    try {
      final r = await _c.get('/api/mdm/devices');
      return (r['devices'] as List?) ?? [];
    } catch (_) { return []; }
  }

  Future<bool> queueMDMCommand(int deviceId, String commandType) async {
    try {
      await _c.post('/api/mdm/devices/$deviceId/commands',
          {'command_type': commandType, 'payload': {}});
      return true;
    } catch (_) { return false; }
  }

  Future<bool> blockMDMDevice(int deviceId) async {
    try { await _c.post('/api/mdm/devices/$deviceId/block', {}); return true; }
    catch (_) { return false; }
  }

  Future<bool> unblockMDMDevice(int deviceId) async {
    try { await _c.post('/api/mdm/devices/$deviceId/unblock', {}); return true; }
    catch (_) { return false; }
  }

  // ── Quarantine ────────────────────────────────────────────────────────────

  Future<List<dynamic>> getQuarantine() async {
    try {
      final r = await _c.get('/api/quarantine');
      if (r['data'] is List) return r['data'] as List;
      return [];
    } catch (_) { return []; }
  }
}
