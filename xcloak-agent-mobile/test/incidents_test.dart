// Tests that the mobile agent's posture/heartbeat payload does not include
// incident-management fields. Incidents are created server-side from alerts;
// the agent only contributes the posture data that feeds alert generation.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Incidents (mobile agent)', () {
    // The mobile agent must never send status, incident_id, or severity fields
    // that could affect incident state on the backend. These are analyst-only
    // mutations that go through authenticated SOC endpoints.
    test('mobile posture excludes incident management fields', () {
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

      const incidentFields = [
        'incident_id', 'status', 'severity',
        'fingerprint', 'title', 'description',
      ];

      for (final field in incidentFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile posture must not include incident field "$field" — '
                'incidents are server-managed');
      }
    });

    // The mobile agent's is_rooted field feeds into risk scoring which can
    // trigger incident creation. Verify it serialises as a bool (not a string
    // like "true"), since the backend alert rule expects a boolean.
    test('is_rooted serialises as bool', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: true,
        developerModeOn: false,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 10,
      );

      final json = posture.toJson();

      expect(json.containsKey('is_rooted'), isTrue,
          reason: 'is_rooted must be present in posture');
      expect(json['is_rooted'], isA<bool>(),
          reason: 'is_rooted must be a bool, not a string');
      expect(json['is_rooted'], isTrue,
          reason: 'is_rooted must reflect the actual value (true)');
    });

    // developer_mode_on feeds into the same alert pipeline. Verify it maps
    // to the key the backend expects from the DevicePosture.toJson() output.
    test('developer_mode_on uses correct JSON key', () {
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
          reason: 'Key must be developer_mode_on (not developer_mode or developerMode)');
      expect(json['developer_mode_on'], isTrue);
    });
  });
}
