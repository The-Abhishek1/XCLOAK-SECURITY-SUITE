// Tests that the mobile agent log submissions match the backend's expected
// contract and that no server-computed search fields leak into the heartbeat.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Log search (mobile exclusion)', () {
    // Mobile heartbeat must not include any log search fields. Log search is
    // a server-side feature — the mobile agent only submits raw log entries
    // via the log ingest endpoint, not via the heartbeat.
    test('mobile heartbeat excludes log search fields', () {
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

      const searchFields = [
        'saved_searches',
        'log_search',
        'search_query',
        'kql',
        'parsed_fields',
        'log_source',
        'retention_days',
        'total_logs',
      ];

      for (final field in searchFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not contain log-search field "$field"');
      }
    });

    // The mobile posture payload keys must be consistent across app versions.
    // Log search's ?source= filter depends on the log_source field being a
    // stable string — any change to key naming breaks existing saved searches.
    test('posture keys are stable and snake_case', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();

      for (final key in json.keys) {
        expect(key, isNot(contains('-')),
            reason: 'Key "$key" uses kebab-case; must be snake_case');
        expect(key, equals(key.toLowerCase()),
            reason: 'Key "$key" must be lowercase snake_case');
      }
    });

    // battery_level must be a non-negative integer (0-100). The log search
    // stats panel uses it as a signal for device health in the by_agent view.
    test('battery_level is a non-negative integer when present', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 42,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      final json = posture.toJson();

      if (json.containsKey('battery_level')) {
        final level = json['battery_level'];
        expect(level, isA<int>(),
            reason: 'battery_level must be an integer, got ${level.runtimeType}');
        expect(level as int, greaterThanOrEqualTo(0));
        expect(level, lessThanOrEqualTo(100));
      }
    });
  });
}
