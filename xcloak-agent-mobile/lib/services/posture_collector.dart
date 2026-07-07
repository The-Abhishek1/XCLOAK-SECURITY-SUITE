import 'dart:io';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:device_info_plus/device_info_plus.dart';

import '../models/device_posture.dart';

// Collects device security posture. Root/developer detection is heuristic —
// covers the vast majority of consumer devices without requiring elevated
// permissions or a Device Owner profile.
class PostureCollector {
  static final _deviceInfo = DeviceInfoPlugin();

  static Future<DevicePosture> collect() async {
    final androidInfo = await _deviceInfo.androidInfo;
    final storage     = await _storageStats();
    final network     = await _networkInfo();
    final battery     = await _batteryInfo();

    return DevicePosture(
      osVersion:           'Android ${androidInfo.version.release}',
      buildVersion:        androidInfo.version.incremental,
      securityPatchLevel:  androidInfo.version.securityPatch ?? '',
      androidSdkVersion:   androidInfo.version.sdkInt,
      manufacturer:        androidInfo.manufacturer,
      hardware:            androidInfo.hardware,
      isEncrypted:         true, // Android 6+ enforces FBE; treat as true
      hasPasscode:         null, // requires DevicePolicyManager method channel
      passcodeCompliant:   null,
      biometricEnrolled:   null,
      isRooted:            await _checkRooted(androidInfo),
      developerModeOn:     androidInfo.version.sdkInt >= 17
                             ? await _checkDeveloperOptions()
                             : false,
      usbDebuggingEnabled: await _checkUsbDebugging(),
      unknownSourcesEnabled: androidInfo.version.sdkInt < 26
                               ? await _checkUnknownSources()
                               : false, // API 26+: per-app setting, not global
      vpnActive:           network['vpn'] as bool,
      batteryLevel:        battery['level'] as int,
      batteryCharging:     battery['charging'] as bool,
      networkType:         network['type'] as String,
      wifiSsid:            network['ssid'] as String,
      storageTotalGb:      storage['total'] as double,
      storageFreeGb:       storage['free'] as double,
      ramTotalMb:          await _ramMb(),
    );
  }

  // ── Root detection ────────────────────────────────────────────────────────

  static Future<bool> _checkRooted(AndroidDeviceInfo info) async {
    if (info.tags.contains('test-keys')) return true;
    const suPaths = [
      '/system/app/Superuser.apk', '/sbin/su', '/system/bin/su',
      '/system/xbin/su', '/data/local/xbin/su', '/data/local/bin/su',
      '/data/local/su', '/system/sd/xbin/su', '/system/bin/failsafe/su',
      '/system/xbin/busybox', '/data/local/tmp/su',
    ];
    for (final path in suPaths) {
      if (await File(path).exists()) return true;
    }
    // Check for Magisk socket
    try {
      final result = await Process.run('test', ['-S', '/dev/.magisk/mirror']);
      if (result.exitCode == 0) return true;
    } catch (_) {}
    return false;
  }

  // ── Developer options / USB debugging ────────────────────────────────────

  static Future<bool> _checkDeveloperOptions() async {
    try {
      // settings get global development_settings_enabled returns "1" when on
      final result = await Process.run(
        'settings', ['get', 'global', 'development_settings_enabled']);
      if (result.stdout.toString().trim() == '1') return true;
    } catch (_) {}
    try {
      // Fallback: ADB over TCP port is set only when wireless debugging is on
      final result = await Process.run('getprop', ['service.adb.tcp.port']);
      if (result.stdout.toString().trim().isNotEmpty) return true;
    } catch (_) {}
    return false;
  }

  static Future<bool> _checkUsbDebugging() async {
    try {
      final result = await Process.run(
        'settings', ['get', 'global', 'adb_enabled']);
      return result.stdout.toString().trim() == '1';
    } catch (_) {
      return false;
    }
  }

  static Future<bool> _checkUnknownSources() async {
    try {
      // API < 26: single global setting
      final result = await Process.run(
        'settings', ['get', 'secure', 'install_non_market_apps']);
      return result.stdout.toString().trim() == '1';
    } catch (_) {
      return false;
    }
  }

  // ── Storage ───────────────────────────────────────────────────────────────

  static Future<Map<String, double>> _storageStats() async {
    try {
      final result = await Process.run('df', ['-h', '/data']);
      final lines = (result.stdout as String).split('\n');
      // df -h /data: Filesystem Size Used Avail Use% Mounted
      if (lines.length >= 2) {
        final fields = lines[1].trim().split(RegExp(r'\s+'));
        if (fields.length >= 4) {
          return {
            'total': _parseSize(fields[1]),
            'free':  _parseSize(fields[3]),
          };
        }
      }
    } catch (_) {}
    return {'total': 0.0, 'free': 0.0};
  }

  static double _parseSize(String s) {
    final match = RegExp(r'([\d.]+)([KMGT]?)').firstMatch(s.toUpperCase());
    if (match == null) return 0;
    final n = double.tryParse(match.group(1)!) ?? 0;
    final unit = match.group(2) ?? '';
    return switch (unit) {
      'K' => n / 1e6,
      'M' => n / 1000,
      'G' => n,
      'T' => n * 1000,
      _   => n / 1e9,
    };
  }

  // ── RAM ───────────────────────────────────────────────────────────────────

  static Future<int> _ramMb() async {
    try {
      final f = File('/proc/meminfo');
      if (await f.exists()) {
        for (final line in await f.readAsLines()) {
          if (line.startsWith('MemTotal:')) {
            final kb = int.tryParse(
              line.replaceAll(RegExp(r'[^0-9]'), '')) ?? 0;
            return (kb / 1024).round();
          }
        }
      }
    } catch (_) {}
    return 0;
  }

  // ── Network ───────────────────────────────────────────────────────────────

  static Future<Map<String, dynamic>> _networkInfo() async {
    String type = 'none';
    String ssid = '';
    bool   vpn  = false;

    try {
      final result = await Connectivity().checkConnectivity();
      // connectivity_plus returns List<ConnectivityResult>
      final results = result is List ? result : [result];
      if (results.contains(ConnectivityResult.wifi)) {
        type = 'wifi';
        // SSID requires location permission on Android 8.1+; best-effort
        try {
          final p = await Process.run('dumpsys', ['wifi']);
          final match = RegExp(r'SSID: ([^\n,]+)').firstMatch(p.stdout as String);
          if (match != null) ssid = match.group(1)!.trim().replaceAll('"', '');
        } catch (_) {}
      } else if (results.contains(ConnectivityResult.mobile)) {
        type = 'mobile';
      } else if (results.contains(ConnectivityResult.ethernet)) {
        type = 'ethernet';
      }
    } catch (_) {}

    // VPN detection via network interface list
    try {
      final interfaces = await NetworkInterface.list();
      vpn = interfaces.any((i) =>
          i.name.startsWith('tun') ||
          i.name.startsWith('ppp') ||
          i.name.startsWith('vpn'));
    } catch (_) {}

    return {'type': type, 'ssid': ssid, 'vpn': vpn};
  }

  // ── Battery ───────────────────────────────────────────────────────────────

  static Future<Map<String, dynamic>> _batteryInfo() async {
    int  level    = -1;
    bool charging = false;
    try {
      final result = await Process.run('dumpsys', ['battery']);
      final out = result.stdout as String;
      final lm = RegExp(r'level: (\d+)').firstMatch(out);
      if (lm != null) level = int.tryParse(lm.group(1)!) ?? -1;
      final sm = RegExp(r'status: (\d+)').firstMatch(out);
      // status 2 = CHARGING, 5 = FULL (also considered "charging")
      if (sm != null) {
        final s = int.tryParse(sm.group(1)!) ?? 0;
        charging = s == 2 || s == 5;
      }
    } catch (_) {}
    return {'level': level, 'charging': charging};
  }

  // ── Device identity ───────────────────────────────────────────────────────

  static Future<String> deviceUDID() async {
    final info = await _deviceInfo.androidInfo;
    return info.id; // ANDROID_ID — stable per-device per-app-signing-key
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
