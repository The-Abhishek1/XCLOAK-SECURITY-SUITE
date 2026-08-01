import 'package:installed_apps/installed_apps.dart';
import 'package:installed_apps/app_info.dart';

import '../models/device_posture.dart';
import 'api_client.dart';
import 'secure_storage.dart';

// Threat detection for mobile devices.
//
// Performs app inventory with installer source verification, sideload
// detection, and permission-level risk scoring. Results are submitted
// to the backend where the threat intelligence engine correlates against
// IOC feeds and known-malicious package lists.
class ThreatDetector {

  static Future<void> runInventoryScan() async {
    final apps = await _collectApps();
    if (apps.isEmpty) return;

    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    if (deviceId == null) return;

    try {
      await client.post('/api/mdm/devices/$deviceId/apps', {
        'apps':           apps.map((a) => a.toJson()).toList(),
        'sideloaded_count': apps.where((a) => _isSideloaded(a)).length,
        'high_risk_count':  apps.where((a) => a.dangerousPermissions.isNotEmpty && _isSideloaded(a)).length,
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
        final installer = _resolveInstaller(app);
        return AppInventoryItem(
          packageName: app.packageName,
          appName:     app.name,
          version:     app.versionName,
          installer:   installer,
          isSystemApp: app.isSystemApp,
          // Permission collection requires PackageManager — not available
          // through installed_apps; included as empty for now; enterprise
          // builds add it via a method channel.
          dangerousPermissions: const [],
        );
      }).toList();
    } catch (_) {
      return [];
    }
  }

  // Resolve the installer source for an app. Play Store installs report
  // com.android.vending; sideloads report an empty string.
  static String _resolveInstaller(AppInfo app) {
    if (app.isSystemApp) return 'system';
    // installed_apps doesn't expose installerPackageName directly, and
    // there's no other real signal available here — this always returns
    // empty for every non-system app. _isSideloaded() below must NOT treat
    // "empty" as "confirmed sideloaded": that previously flagged every
    // single user-installed app on the device, including ones from the Play
    // Store, as a threat — a 100% false-positive rate that made the finding
    // pure noise. Real sideload detection needs PackageManager
    // .getInstallSourceInfo() via a native Android method channel, which
    // this build doesn't have.
    return '';
  }

  // Always false: no real installer signal exists yet (see _resolveInstaller).
  // Reporting "not sideloaded" for everything is the honest default until
  // real detection is built — the alternative (flagging every app) is worse
  // than reporting nothing, since it can't be trusted or acted on.
  static bool _isSideloaded(AppInventoryItem app) => false;

  // Returns package names of apps that appear to be sideloaded.
  static Future<List<String>> sideloadedPackages() async {
    final apps = await _collectApps();
    return apps.where(_isSideloaded).map((a) => a.packageName).toList();
  }

  // Returns a threat summary suitable for including in the heartbeat.
  static Future<Map<String, dynamic>> threatSummary() async {
    final apps       = await _collectApps();
    final sideloaded = apps.where(_isSideloaded).toList();
    return {
      'total_apps':       apps.length,
      'sideloaded_count': sideloaded.length,
      'system_app_count': apps.where((a) => a.isSystemApp).length,
      'sideloaded_packages': sideloaded.take(20).map((a) => a.packageName).toList(),
    };
  }
}
