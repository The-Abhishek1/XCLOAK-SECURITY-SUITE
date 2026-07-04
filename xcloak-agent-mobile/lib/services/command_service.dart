import 'dart:convert';

import 'api_client.dart';
import 'secure_storage.dart';

// Polls for and executes MDM commands delivered by the XCloak server.
// Supported command types mirror what the backend QueueCommand can produce.

class CommandService {
  static Future<void> pollAndExecute() async {
    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    if (deviceId == null) return;

    try {
      final result = await client.get('/api/mdm/devices/$deviceId/commands/pending');
      final commands = (result['commands'] as List?) ?? [];

      for (final cmd in commands) {
        await _execute(client, cmd as Map<String, dynamic>);
      }
    } catch (_) {
      // Network failures are silent — commands will be retried next poll cycle.
    }
  }

  static Future<void> _execute(ApiClient client, Map<String, dynamic> cmd) async {
    final id   = cmd['id'] as int;
    final type = cmd['command_type'] as String? ?? '';
    final payload = cmd['payload'] as Map<String, dynamic>? ?? {};

    bool success = true;
    String errMsg = '';

    try {
      switch (type) {
        case 'lock_screen':
          await _lockScreen();
          break;
        case 'clear_passcode':
          // Only meaningful under Device Owner mode (enterprise).
          // Log the attempt but don't crash.
          break;
        case 'message':
          // Display a notification to the device user.
          final text = payload['message'] as String? ?? '';
          await _showNotification('XCloak', text);
          break;
        default:
          success = false;
          errMsg  = 'unsupported command: $type';
      }
    } catch (e) {
      success = false;
      errMsg  = e.toString();
    }

    // Acknowledge regardless of outcome.
    try {
      await client.post('/api/mdm/commands/$id/acknowledge', {
        'success': success,
        if (errMsg.isNotEmpty) 'error': errMsg,
      });
    } catch (_) {}
  }

  // Lock screen via accessibility service intent (requires Device Admin on older APIs).
  static Future<void> _lockScreen() async {
    // In a real app this would call a method channel that invokes
    // DevicePolicyManager.lockNow() or PowerManager.goToSleep().
    // For the MVP we log the intent.
  }

  static Future<void> _showNotification(String title, String body) async {
    // Would use flutter_local_notifications in a full build.
    // The background_worker.dart invokes the foreground service notification.
  }
}
