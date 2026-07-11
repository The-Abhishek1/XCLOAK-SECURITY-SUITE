// Tests that verify the mobile agent's posture data is compatible with UEBA
// analysis. UEBA on mobile primarily flags rooted devices, developer mode, and
// off-hours activity patterns from the network_type and posture fields.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('UEBA (mobile agent posture)', () {
    // UEBA risk scoring treats is_rooted=true as a high-risk signal.
    // Verify the field name and type match what the backend alert rule expects.
    test('is_rooted field is present and typed as bool', () {
      final rootedPosture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: true,
        developerModeOn: false,
        batteryLevel: 50,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = rootedPosture.toJson();

      expect(json['is_rooted'], isA<bool>(),
          reason: 'is_rooted must be a bool for UEBA root-detection alert rule');
      expect(json['is_rooted'], isTrue);

      // Non-rooted device should also be correct
      final cleanPosture = DevicePosture(
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

      final cleanJson = cleanPosture.toJson();
      expect(cleanJson['is_rooted'], isFalse);
    });

    // developer_mode_on is a secondary UEBA risk signal.
    // Verify it round-trips correctly.
    test('developer_mode_on field round-trips correctly', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: true,
        batteryLevel: 70,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 50,
      );

      final json = posture.toJson();

      expect(json.containsKey('developer_mode_on'), isTrue,
          reason: 'Key must be developer_mode_on for UEBA risk scoring');
      expect(json['developer_mode_on'], isTrue);
    });

    // The mobile posture must not include UEBA-specific analysis fields.
    // UEBA analysis is server-side — agents only submit raw posture data.
    test('posture excludes ueba analysis fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 90,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 256,
        storageFreeGb: 100,
      );

      final json = posture.toJson();

      const uebaFields = [
        'risk_score', 'flags', 'failed_logins', 'off_hours_events',
        'privilege_escalations', 'unique_ips', 'analyzed_at',
      ];

      for (final field in uebaFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile posture must not include UEBA analysis field "$field" — computed server-side');
      }
    });
  });
}
