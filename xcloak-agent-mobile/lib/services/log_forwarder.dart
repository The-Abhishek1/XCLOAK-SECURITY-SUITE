import 'dart:io';

import 'api_client.dart';
import 'secure_storage.dart';

// Collects and forwards Android security-relevant log lines to XCloak.
//
// Full logcat access is restricted without root; this service collects what
// the app's own process can see plus security/crash/package-change metadata.
// In a Device Owner (enterprise) deployment, the system logcat API via a
// platform method channel would give broader access.

class LogForwarder {
  // Log tags that carry the most security signal without requiring root.
  static const _tags = [
    'AndroidRuntime',    // crash / Dalvik VM errors
    'ActivityManager',   // app lifecycle — detects unexpected starts
    'PackageManager',    // install / uninstall events (sideload detection)
    'PackageInstaller',  // APK staging events
    'KeyStore',          // cryptographic op errors
    'SELinux',           // SELinux denials → privilege escalation attempts
    'Binder',            // IPC exceptions — useful for exploit detection
    'WifiService',       // WiFi association events
    'NetworkService',    // VPN state changes
    'AccessibilityService', // accessibility service bind attempts
    'DevicePolicyManager',  // MDM policy enforcement log
  ];

  static Future<void> forwardBatch() async {
    final logs = await _collectLogs();
    if (logs.isEmpty) return;

    final client  = await ApiClient.fromStorage();
    final agentId = await SecureStore.agentId();
    if (agentId == null) return;

    try {
      await client.post('/api/logs/ingest', {
        'agent_id': agentId,
        'log_source': 'android_agent',
        'logs': logs,
      });
    } catch (_) {}
  }

  static Future<List<Map<String, dynamic>>> _collectLogs() async {
    final now = DateTime.now().toUtc().toIso8601String();
    try {
      final tagArgs = _tags.expand((t) => ['-s', t]).toList();
      final result  = await Process.run('logcat', ['-d', '-t', '200', ...tagArgs]);
      if (result.exitCode != 0) return [];
      return (result.stdout as String)
          .split('\n')
          .where((l) => l.trim().isNotEmpty)
          .take(200)
          .map((line) => {
                'log_source':  'android_agent',
                'log_message': line,
                'severity':    _parseSeverity(line),
                'collected_at': now,
              })
          .toList();
    } catch (_) {
      return [];
    }
  }

  // Android logcat severity: V/D/I/W/E/F → maps to syslog-style labels.
  static String _parseSeverity(String line) {
    if (line.length < 2) return 'info';
    final lvl = line[0];
    return switch (lvl) {
      'F' || 'A' => 'critical',
      'E'        => 'error',
      'W'        => 'warning',
      'I'        => 'info',
      _          => 'debug',
    };
  }
}
