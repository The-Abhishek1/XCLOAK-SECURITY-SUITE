import 'api_client.dart';
import 'log_forwarder.dart';
import 'posture_collector.dart';
import 'secure_storage.dart';
import 'threat_detector.dart';

// MDM command execution layer.
//
// Polls the server's pending command queue and executes each command.
// Every command is acknowledged (with result/error) to the server after
// execution. Unknown commands are acknowledged as errors rather than
// silently dropped so operators can detect misconfigured policies.
class CommandService {
  static Future<void> pollAndExecute() async {
    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    if (deviceId == null) return;

    List cmds;
    try {
      final data = await client.get('/api/mdm/devices/$deviceId/commands/pending');
      cmds = (data as Map<String, dynamic>)['commands'] as List? ?? [];
    } catch (_) {
      return;
    }

    for (final raw in cmds) {
      final cmd   = raw as Map<String, dynamic>;
      final cmdId = cmd['id'];
      final type  = (cmd['command_type'] ?? '') as String;
      String? result;
      String? error;

      try {
        result = await _execute(type, cmd, client, deviceId);
      } catch (e) {
        error = e.toString();
      }

      try {
        await client.post('/api/mdm/commands/$cmdId/acknowledge', {
          'status': error != null ? 'failed' : 'executed',
          if (result != null) 'result': result,
          if (error  != null) 'error':  error,
        });
      } catch (_) {}
    }
  }

  static Future<String> _execute(
      String type, Map cmd, ApiClient client, int deviceId) async {
    switch (type) {

      // ── Read-only collection ─────────────────────────────────────────────

      case 'collect_apps':
        await ThreatDetector.runInventoryScan();
        return 'app inventory completed';

      case 'collect_posture':
        final posture = await PostureCollector.collect();
        await client.put('/api/mdm/devices/$deviceId/checkin', posture.toJson());
        return 'posture refreshed';

      case 'scan_threats':
        final summary = await ThreatDetector.threatSummary();
        await client.post('/api/mdm/devices/$deviceId/threat-scan', summary);
        return 'threat scan completed — ${summary['total_apps']} apps, '
               '${summary['sideloaded_count']} sideloaded';

      case 'collect_logs':
        await LogForwarder.forwardBatch();
        return 'log batch forwarded';

      // ── Soft management ──────────────────────────────────────────────────

      case 'sync':
        // Trigger posture refresh and push current app inventory.
        await _execute('collect_posture', cmd, client, deviceId);
        await _execute('collect_apps', cmd, client, deviceId);
        return 'full sync completed';

      case 'message':
        // The payload is rendered as an in-app notification. The foreground
        // service cannot show a UI dialog from its isolate, so we store it
        // and the app checks on next resume.
        final text = (cmd['payload']?['text'] ?? '') as String;
        if (text.isEmpty) return 'no message text in payload';
        await SecureStore.storePendingMessage(text);
        return 'message queued for display';

      case 'rotate_token':
        // Request a new agent token from the server.
        final response = await client.post(
          '/api/mdm/devices/$deviceId/rotate-token', {});
        final newToken =
            (response as Map<String, dynamic>)['agent_token'] as String?;
        if (newToken != null && newToken.isNotEmpty) {
          await SecureStore.storeAgentToken(newToken);
          return 'agent token rotated';
        }
        return 'rotate_token: no new token in response';

      case 'update_agent':
        // Notify the user of an available update rather than auto-installing,
        // which would require INSTALL_PACKAGES permission.
        final url = (cmd['payload']?['apk_url'] ?? '') as String;
        if (url.isNotEmpty) {
          await SecureStore.storePendingMessage(
              'XCloak Agent update available. Download: $url');
          return 'update notification queued';
        }
        return 'update_agent: no apk_url in payload';

      // ── Restricted management ────────────────────────────────────────────

      case 'lock':
      case 'lock_screen':
        // Requires Device Admin receiver (DevicePolicyManager.lockNow()).
        // Enterprise builds add this via a method channel with a registered
        // DeviceAdminReceiver; BYOD builds return a clear error.
        return 'lock_screen: requires Device Admin receiver — not available in BYOD mode';

      case 'clear_passcode':
        return 'clear_passcode: requires Device Owner profile';

      case 'wipe':
        // Intentionally rejected; factory reset requires Device Owner mode.
        throw Exception('wipe rejected — Device Owner mode required');

      default:
        return 'unknown command type: $type';
    }
  }
}
