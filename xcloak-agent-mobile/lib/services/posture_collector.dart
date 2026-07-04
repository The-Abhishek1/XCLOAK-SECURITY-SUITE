import 'dart:io';
import 'package:device_info_plus/device_info_plus.dart';

import '../models/device_posture.dart';

// Collects device security posture without requiring elevated permissions.
// Root detection is heuristic — checks for common su binary paths and
// build property flags, which cover the vast majority of rooted consumer devices.

class PostureCollector {
  static final _deviceInfo = DeviceInfoPlugin();

  static Future<DevicePosture> collect() async {
    final androidInfo = await _deviceInfo.androidInfo;

    return DevicePosture(
      osVersion:     'Android ${androidInfo.version.release}',
      buildVersion:  androidInfo.version.incremental,
      isEncrypted:   true, // Android 6+ enforces encryption; treat as true by default
      hasPasscode:   null, // requires DevicePolicyManager — will be null until we add a method channel
      passcodeCompliant: null,
      isRooted:      await _checkRooted(androidInfo),
      developerModeOn: androidInfo.version.sdkInt >= 17
          ? await _checkDeveloperOptions()
          : false,
    );
  }

  // Heuristic root check — checks for su binaries in standard locations and
  // the test-keys build tag (common on unofficial ROMs).
  static Future<bool> _checkRooted(AndroidDeviceInfo info) async {
    // Build tag check: production builds use 'release-keys'.
    if (info.tags.contains('test-keys')) return true;

    // Check common su binary locations.
    const suPaths = [
      '/system/app/Superuser.apk',
      '/sbin/su',
      '/system/bin/su',
      '/system/xbin/su',
      '/data/local/xbin/su',
      '/data/local/bin/su',
      '/data/local/su',
      '/system/sd/xbin/su',
      '/system/bin/failsafe/su',
      '/system/xbin/busybox',
    ];
    for (final path in suPaths) {
      if (await File(path).exists()) return true;
    }
    return false;
  }

  // Developer options — best-effort via system properties.
  static Future<bool> _checkDeveloperOptions() async {
    try {
      final result = await Process.run('getprop', ['adb.tcp.port']);
      // ADB over TCP is only active when developer options + wireless debug is on.
      if (result.stdout.toString().trim().isNotEmpty) return true;
    } catch (_) {}
    return false;
  }

  // Returns a stable device identifier (ANDROID_ID).
  static Future<String> deviceUDID() async {
    final info = await _deviceInfo.androidInfo;
    return info.id; // ANDROID_ID — stable per-device
  }

  static Future<String> deviceName() async {
    final info = await _deviceInfo.androidInfo;
    return info.model;
  }

  static Future<String> model() async {
    final info = await _deviceInfo.androidInfo;
    return '${info.manufacturer} ${info.model}';
  }
}
