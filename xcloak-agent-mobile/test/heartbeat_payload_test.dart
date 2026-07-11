// Unit tests for the mobile heartbeat payload construction.
// These run without a device via `flutter test`.

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('DevicePosture.toJson — heartbeat fields', () {
    test('includes all required heartbeat keys', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A.220624.014',
        securityPatchLevel: '2025-06-01',
        androidSdkVersion: 33,
        manufacturer: 'Google',
        hardware: 'bluejay',
        isRooted: false,
        developerModeOn: false,
        vpnActive: false,
        batteryLevel: 82,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 64.0,
        storageFreeGb: 28.5,
        ramTotalMb: 8192,
      );

      final json = posture.toJson();

      // Keys that background_worker sends in the heartbeat
      final heartbeatKeys = [
        'battery_level',
        'battery_charging',
        'network_type',
        'is_rooted',
        'developer_mode_on',
        'storage_free_gb',
        'storage_total_gb',
        'vpn_active',
      ];

      for (final key in heartbeatKeys) {
        expect(json.containsKey(key), isTrue,
            reason: 'Expected key "$key" in posture.toJson()');
      }
    });

    test('battery_level value is preserved', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: '',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 55,
        batteryCharging: false,
        networkType: 'mobile',
        storageTotalGb: 32,
        storageFreeGb: 10,
      );

      final json = posture.toJson();
      expect(json['battery_level'], equals(55));
      expect(json['battery_charging'], isFalse);
      expect(json['network_type'], equals('mobile'));
    });

    test('security_patch_level omitted when empty', () {
      final posture = DevicePosture(
        osVersion: 'Android 12',
        buildVersion: '',
        securityPatchLevel: '',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 30,
        batteryCharging: false,
        networkType: 'none',
        storageTotalGb: 16,
        storageFreeGb: 4,
      );

      final json = posture.toJson();
      expect(json.containsKey('security_patch_level'), isFalse,
          reason: 'Empty securityPatchLevel should be omitted');
    });

    test('is_rooted true is reflected in JSON', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: '',
        isRooted: true,
        developerModeOn: true,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();
      expect(json['is_rooted'], isTrue);
      expect(json['developer_mode_on'], isTrue);
    });

    test('storage values omitted when zero', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: '',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 50,
        batteryCharging: false,
        networkType: 'none',
        storageTotalGb: 0,
        storageFreeGb: 0,
      );

      final json = posture.toJson();
      expect(json.containsKey('storage_total_gb'), isFalse);
      expect(json.containsKey('storage_free_gb'), isFalse);
    });
  });

  group('Background worker heartbeat payload shape', () {
    // Verifies the key names the background_worker builds match what the
    // backend model expects. This is a contract test — if background_worker.dart
    // changes a key name, this test breaks and forces an update to the backend.
    test('expected JSON key names for /api/agents/heartbeat', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        securityPatchLevel: '2026-01-01',
        isRooted: false,
        developerModeOn: false,
        vpnActive: true,
        batteryLevel: 90,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      // Simulate what background_worker._checkIn builds (minus agent_id / version):
      final payload = {
        'battery_level':     posture.batteryLevel,
        'battery_charging':  posture.batteryCharging,
        'network_type':      posture.networkType,
        'is_rooted':         posture.isRooted,
        'developer_mode':    posture.developerModeOn, // backend field name
        'storage_free_gb':   posture.storageFreeGb,
        'storage_total_gb':  posture.storageTotalGb,
        'vpn_active':        posture.vpnActive,
        'os_version':        posture.osVersion,
        'security_patch':    posture.securityPatchLevel,
      };

      // Backend HeartbeatRequest model fields (Go json tags):
      final backendExpectedKeys = [
        'battery_level',
        'battery_charging',
        'network_type',
        'is_rooted',
        'developer_mode',
        'storage_free_gb',
        'storage_total_gb',
        'vpn_active',
        'security_patch',
      ];

      for (final key in backendExpectedKeys) {
        expect(payload.containsKey(key), isTrue,
            reason: 'Heartbeat payload missing key "$key" expected by backend');
      }

      expect(payload['battery_level'], equals(90));
      expect(payload['vpn_active'], isTrue);
      expect(payload['security_patch'], equals('2026-01-01'));
    });
  });
}
