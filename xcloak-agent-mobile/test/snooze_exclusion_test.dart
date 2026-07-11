// Tests that mobile agent payloads do not carry alert-management state.
// Snooze (suppressed_until) is a server-side concern; the agent must never
// send or reset it, or the backend would treat a client value as authoritative.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Alert snooze exclusion (mobile)', () {
    // The mobile heartbeat payload must NOT include any server-managed
    // alert state. Sending these would let an agent bypass server-side
    // access controls (e.g., a compromised device re-opening snoozed alerts).
    test('mobile heartbeat excludes all alert management fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 80,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      final json = posture.toJson();

      const serverManagedFields = [
        'suppressed_until',
        'snooze_until',
        'status',
        'acknowledged_by',
        'acknowledged_at',
        'note',
        'ai_summary',
        'ai_action',
        'ai_triaged_at',
        'fingerprint',
        'rule_name',
        'severity',
      ];

      for (final field in serverManagedFields) {
        expect(json.containsKey(field), isFalse,
            reason: 'Mobile heartbeat must not include server-managed field "$field"');
      }
    });

    // The heartbeat payload must include only posture fields that describe
    // the current state of the device — not historical or aggregated fields.
    test('mobile heartbeat contains expected posture keys', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 70,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
        vpnActive: false,
      );

      final json = posture.toJson();

      const requiredPostureKeys = [
        'battery_level',
        'battery_charging',
        'network_type',
        'storage_total_gb',
        'storage_free_gb',
        'is_rooted',
        'developer_mode_on',
      ];

      for (final key in requiredPostureKeys) {
        expect(json.containsKey(key), isTrue,
            reason: 'Mobile posture payload missing required field "$key"');
      }
    });

    // Verify that is_rooted=true doesn't get silently coerced to false.
    // A compromised device that could clear this flag would evade detection
    // regardless of snooze state — the value must be boolean and accurate.
    test('is_rooted cannot be falsified by type coercion', () {
      final rootedDevice = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: true,
        developerModeOn: true,
        batteryLevel: 45,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 32,
        storageFreeGb: 5,
      );

      final json = rootedDevice.toJson();

      // Confirm it's strictly boolean true, not truthy-string or 1.
      expect(json['is_rooted'], equals(true));
      expect(json['is_rooted'], isA<bool>());
      expect(json['is_rooted'], isNot(equals(1)));
      expect(json['is_rooted'], isNot(equals('true')));
    });

    // An empty/minimal DevicePosture must still serialize without errors —
    // the backend must handle missing optional fields (like security_patch_level)
    // without crashing.
    test('minimal posture serializes without errors', () {
      final minimal = DevicePosture(
        osVersion: '',
        buildVersion: '',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 0,
        batteryCharging: false,
        networkType: 'none',
        storageTotalGb: 0,
        storageFreeGb: 0,
      );

      Map<String, dynamic>? json;
      expect(() => json = minimal.toJson(), returnsNormally);
      expect(json, isNotNull);
      expect(json!['is_rooted'], isFalse);
    });
  });
}
