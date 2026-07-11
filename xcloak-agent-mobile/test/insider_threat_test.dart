// Tests that mobile agent posture fields that feed insider threat scoring
// are present and correctly typed. The insider threat engine uses is_rooted,
// developer_mode_on, and vpn_active as risk signals for mobile devices.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Insider threat (mobile posture signals)', () {
    // is_rooted is a high-severity insider threat signal for mobile. A rooted
    // device bypasses OS security controls and is flagged as a critical risk.
    // Verify the field is a bool so the backend alert rule can compare it.
    test('is_rooted is a bool and not a string', () {
      for (final rooted in [true, false]) {
        final posture = DevicePosture(
          osVersion: 'Android 14',
          buildVersion: 'UP1A',
          isRooted: rooted,
          developerModeOn: false,
          batteryLevel: 80,
          batteryCharging: true,
          networkType: 'wifi',
          storageTotalGb: 128,
          storageFreeGb: 64,
        );

        final json = posture.toJson();
        expect(json['is_rooted'], equals(rooted),
            reason: 'is_rooted must equal $rooted');
        expect(json['is_rooted'], isA<bool>(),
            reason: 'is_rooted must be bool, not string or int');
      }
    });

    // vpn_active is used as an anomalous-location indicator. A device suddenly
    // without VPN in a sensitive environment raises the anomalous_location signal.
    test('vpn_active field is a bool when present', () {
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
      if (json.containsKey('vpn_active')) {
        expect(json['vpn_active'], isA<bool>(),
            reason: 'vpn_active must be bool for insider threat location scoring');
      }
      // Field is optional — absence is OK (server treats missing as false)
    });

    // Mobile posture must not include pre-computed insider threat fields.
    // These are server-side analytics results, not agent-submitted data.
    test('posture excludes insider threat computed fields', () {
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

      const insiderFields = [
        'score', 'risk_level', 'contributors', 'alert_fired',
        'off_hours_auth', 'failed_auth', 'data_exfil',
        'sensitive_access', 'privesc_attempt', 'anomalous_location',
      ];

      for (final field in insiderFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile posture must not include insider threat field "$field" — computed server-side');
      }
    });
  });
}
