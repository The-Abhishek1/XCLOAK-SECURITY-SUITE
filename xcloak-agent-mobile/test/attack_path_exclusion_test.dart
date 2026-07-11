// Tests that mobile agent payloads do not carry attack-path graph fields.
// Attack-path nodes/edges are built entirely server-side from connection streams
// and vulnerability data. A compromised phone sending these fields could
// manipulate the SOC's view of which nodes are "exposed" or have high pivot cost.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Attack path exclusion (mobile)', () {
    // The mobile heartbeat must NOT include fields from the attack-path data
    // model. These are all computed server-side from network topology.
    test('mobile heartbeat excludes all attack-path graph fields', () {
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

      const attackPathFields = [
        'nodes',
        'edges',
        'top_paths',
        'has_entry_point',
        'compromise_cost',
        'risk_score',
        'max_epss',
        'has_kev',
        'kev_count',
        'exposed',
        'open_alert_count',
        'hops',
        'total_cost',
        'target_risk_level',
      ];

      for (final field in attackPathFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not include attack-path field "$field"');
      }
    });

    // is_rooted is the mobile equivalent of "exposed" in the attack-path
    // model — but it's a device posture signal, not a topology signal.
    // Ensure the key names don't bleed across models.
    test('is_rooted is posture signal, not exposed topology signal', () {
      final rootedPosture = DevicePosture(
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

      final json = rootedPosture.toJson();

      // Mobile uses is_rooted, NOT "exposed" (which is the attack-path field)
      expect(json.containsKey('is_rooted'), isTrue);
      expect(json['is_rooted'], isTrue);
      expect(json.containsKey('exposed'), isFalse,
          reason: '"exposed" is an attack-path topology field, not device posture');
    });
  });
}
