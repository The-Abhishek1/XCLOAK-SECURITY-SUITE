// Tests that mobile agent posture fields are compatible with the behavioral
// threat detection backend. The threat detection engine scores agents using
// fields reported in the device posture check-in payload.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Threat Detection (mobile posture fields)', () {
    // The behavioral scoring engine uses is_rooted and developer_mode_on as
    // elevated-risk signals. Verify they are present as booleans.
    test('posture includes rooted and developer_mode_on as booleans', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: true,
        developerModeOn: true,
        batteryLevel: 80,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      final json = posture.toJson();
      expect(json['is_rooted'], isA<bool>(),
          reason: 'is_rooted must be bool — used as high-risk signal in threat scoring');
      expect(json['developer_mode_on'], isA<bool>(),
          reason: 'developer_mode_on must be bool — used as medium-risk signal in threat scoring');
      expect(json['is_rooted'], isTrue);
      expect(json['developer_mode_on'], isTrue);
    });

    // Threat detection output fields (scores, findings) are computed server-side.
    // The mobile agent must not embed these in the posture payload.
    test('posture excludes threat detection output fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 90,
        batteryCharging: true,
        networkType: 'lte',
        storageTotalGb: 256,
        storageFreeGb: 100,
      );

      final json = posture.toJson();

      const threatFields = [
        'score', 'anomaly_score', 'finding_type', 'acknowledged',
        'components', 'peak_score', 'avg_score',
      ];

      for (final field in threatFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Posture must not contain threat scoring field "$field" — server-computed');
      }
    });

    // battery_level is used by the threat scoring engine as a proxy for
    // sustained suspicious activity (battery drain from crypto mining, etc.).
    // It must be an integer in [0, 100].
    test('battery_level is an integer in valid range', () {
      for (final level in [0, 50, 100]) {
        final posture = DevicePosture(
          osVersion: 'Android 14',
          buildVersion: 'UP1A',
          isRooted: false,
          developerModeOn: false,
          batteryLevel: level,
          batteryCharging: false,
          networkType: 'wifi',
          storageTotalGb: 64,
          storageFreeGb: 20,
        );

        final json = posture.toJson();
        expect(json['battery_level'], isA<int>(),
            reason: 'battery_level must be int for threat scoring signals');
        expect(json['battery_level'] as int, greaterThanOrEqualTo(0));
        expect(json['battery_level'] as int, lessThanOrEqualTo(100));
      }
    });
  });
}
