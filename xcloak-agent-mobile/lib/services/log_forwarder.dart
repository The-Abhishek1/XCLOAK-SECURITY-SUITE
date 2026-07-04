import 'dart:io';

import 'api_client.dart';
import 'secure_storage.dart';

// Collects and forwards Android security-relevant log lines to XCloak.
//
// Full logcat access is restricted without root; this service collects only
// what the app's own process can see plus crash/ANR metadata. In a Device
// Owner (enterprise) deployment, adb shell logcat can be replaced with the
// system logcat API via a platform method channel.

class LogForwarder {
  static Future<void> forwardBatch() async {
    final logs = await _collectLogs();
    if (logs.isEmpty) return;

    final client  = await ApiClient.fromStorage();
    final agentId = await SecureStore.agentId();
    if (agentId == null) return;

    // Reuse the standard log ingest endpoint with source=android_agent.
    try {
      await client.post('/api/logs/ingest', {
        'agent_id': agentId,
        'logs': logs.map((l) => {
          'log_source': 'android_agent',
          'log_message': l,
          'collected_at': DateTime.now().toUtc().toIso8601String(),
        }).toList(),
      });
    } catch (_) {}
  }

  // Collects the most recent security-relevant logcat lines that the app
  // process is permitted to read (typically its own logs + system warnings).
  static Future<List<String>> _collectLogs() async {
    try {
      final result = await Process.run(
        'logcat',
        ['-d', '-t', '100', '-s', 'AndroidRuntime', 'ActivityManager', 'PackageManager', 'KeyStore'],
      );
      if (result.exitCode != 0) return [];
      return (result.stdout as String)
          .split('\n')
          .where((l) => l.trim().isNotEmpty)
          .take(100)
          .toList();
    } catch (_) {
      return [];
    }
  }
}
