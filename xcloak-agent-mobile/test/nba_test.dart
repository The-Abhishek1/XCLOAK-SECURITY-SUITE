// Tests that mobile agent posture and network fields are compatible with the
// NBA (Network Behavior Analytics) backend. The mobile agent reports
// network_type and wifi_ssid which the NBA engine uses for anomalous-location
// detection alongside the posture data.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('NBA (mobile network fields)', () {
    // network_type is used by NBA to detect protocol anomalies for mobile.
    // The backend expects it as a string (wifi, lte, 5g, etc.).
    test('network_type is a string in posture payload', () {
      for (final networkType in ['wifi', 'lte', '5g', 'none']) {
        final posture = DevicePosture(
          osVersion: 'Android 14',
          buildVersion: 'UP1A',
          isRooted: false,
          developerModeOn: false,
          batteryLevel: 80,
          batteryCharging: true,
          networkType: networkType,
          storageTotalGb: 128,
          storageFreeGb: 64,
        );

        final json = posture.toJson();
        expect(json['network_type'], equals(networkType),
            reason: 'network_type must equal $networkType');
        expect(json['network_type'], isA<String>(),
            reason: 'network_type must be a String for NBA protocol detection');
      }
    });

    // Mobile posture must not include NBA analysis fields. Network anomalies
    // are computed server-side from connection event data; the mobile agent
    // only reports the device posture and check-in data.
    test('posture excludes NBA analysis output fields', () {
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

      const nbaFields = [
        'anomaly_type', 'deviation_score', 'is_acknowledged',
        'dst_ip', 'dst_port', 'baseline', 'anomalies',
      ];

      for (final field in nbaFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile posture must not include NBA field "$field" — server-computed');
      }
    });

    // vpn_active is reported by the mobile agent and used by the NBA engine
    // as an anomalous-location signal. Verify it's a bool when present.
    test('vpn_active is a bool when present', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 75,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();
      if (json.containsKey('vpn_active')) {
        expect(json['vpn_active'], isA<bool>(),
            reason: 'vpn_active must be bool for NBA location anomaly detection');
      }
    });
  });
}
