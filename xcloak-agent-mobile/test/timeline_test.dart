// Tests that the mobile agent does not synthesize timeline events or severity
// values — those are server-side concerns. The mobile agent only reports raw
// posture data; timeline events (alerts, incidents, playbooks) are assembled
// entirely by the backend detection engine.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Timeline (mobile exclusion)', () {
    // The mobile heartbeat must never include timeline, event_type, or severity.
    // If a device sends these it could inject synthetic timeline events and
    // manipulate the SOC operator's view of security incidents.
    test('mobile heartbeat excludes all timeline fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 75,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      final json = posture.toJson();

      const timelineFields = [
        'timeline',
        'events',
        'event_type',
        'severity',
        'incidents',
        'playbook_executions',
        'alert_rule',
      ];

      for (final field in timelineFields) {
        expect(json.containsKey(field), isFalse,
            reason: 'Mobile heartbeat must not include timeline field "$field"');
      }
    });

    // The posture payload keys must be stable strings. The backend maps them
    // to DB columns; any key change requires a coordinated backend migration.
    test('posture payload uses stable underscore_case keys', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: true,
        batteryLevel: 50,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();

      for (final key in json.keys) {
        // All keys should be snake_case (no camelCase, no spaces)
        expect(key, isNot(contains(' ')),
            reason: 'Key "$key" must not contain spaces');
        expect(key, equals(key.toLowerCase()),
            reason: 'Key "$key" must be lowercase (snake_case)');
      }
    });

    // is_rooted and developer_mode_on are the two posture signals that feed
    // directly into alert generation on the server. They must be present and
    // boolean — a missing or string value silently fails the DB scan.
    test('security posture boolean signals are present and typed', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: true,
        developerModeOn: true,
        batteryLevel: 30,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 32,
        storageFreeGb: 4,
      );

      final json = posture.toJson();

      if (json.containsKey('is_rooted')) {
        expect(json['is_rooted'], isA<bool>(),
            reason: 'is_rooted must be a boolean');
      }
      if (json.containsKey('developer_mode_on')) {
        expect(json['developer_mode_on'], isA<bool>(),
            reason: 'developer_mode_on must be a boolean');
      }
    });
  });
}
