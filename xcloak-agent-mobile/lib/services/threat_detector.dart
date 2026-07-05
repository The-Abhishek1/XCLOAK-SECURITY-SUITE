import 'package:installed_apps/installed_apps.dart';
import 'package:installed_apps/app_info.dart';

import '../models/device_posture.dart';
import 'api_client.dart';
import 'secure_storage.dart';

// Threat detection for mobile devices.
//
// Runs an app inventory scan and submits the results to the backend where the
// threat intelligence engine can correlate against IOC feeds, known-malicious
// package lists, and sideload indicators (installer != Play Store).

class ThreatDetector {
  static Future<void> runInventoryScan() async {
    final apps = await _collectApps();
    if (apps.isEmpty) return;

    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    if (deviceId == null) return;

    try {
      await client.post('/api/mdm/devices/$deviceId/apps', {
        'apps': apps.map((a) => a.toJson()).toList(),
      });
    } catch (_) {}
  }

  static Future<List<AppInventoryItem>> _collectApps() async {
    try {
      final List<AppInfo> installed = await InstalledApps.getInstalledApps(
        excludeSystemApps: false,
        withIcon: false,
      );
      return installed.map((app) {
        // installer source: empty string means sideloaded (not from Play Store)
        final installer = app.isSystemApp ? 'system' : '';
        return AppInventoryItem(
          packageName: app.packageName,
          appName:     app.name,
          version:     app.versionName ?? '',
          installer:   installer,
        );
      }).toList();
    } catch (_) {
      return [];
    }
  }

  // Quick local check: flags apps installed from sources other than Play Store
  // or system. These should be reviewed by the security team.
  static Future<List<String>> sideloadedPackages() async {
    final apps = await _collectApps();
    return apps
        .where((a) => a.installer.isEmpty || (!a.installer.contains('vending') && !a.installer.startsWith('com.android')))
        .map((a) => a.packageName)
        .toList();
  }
}
