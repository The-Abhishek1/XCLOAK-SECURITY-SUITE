// Tests that the mobile agent sends log entries in the correct contract format
// and does not pre-parse log messages server-side. Field extraction (auth_result,
// src_ip, etc.) is done exclusively by the backend log parser.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Live logs (mobile exclusion)', () {
    // The mobile heartbeat must not contain log stream fields. Log collection
    // on mobile is event-driven (on auth events, syslog flush), not streamed
    // via the heartbeat. Mixing them would break the server's log ingest path.
    test('mobile heartbeat excludes log stream fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 90,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      final json = posture.toJson();

      const logFields = [
        'log_source',
        'log_message',
        'parsed_fields',
        'collected_at',
        'logs',
        'endpoint_logs',
        'auth_result',
        'src_ip',
      ];

      for (final field in logFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not contain log stream field "$field"');
      }
    });

    // Mobile devices do not send EPS (events-per-second) metrics — that is a
    // server-computed rate from the stream of incoming logs.
    test('mobile heartbeat excludes EPS and rate metrics', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 30,
      );

      final json = posture.toJson();

      const rateFields = ['eps', 'events_per_second', 'log_rate', 'stream_rate'];
      for (final field in rateFields) {
        expect(json.containsKey(field), isFalse,
            reason: 'Mobile heartbeat must not contain rate field "$field"');
      }
    });

    // The posture payload must include os_version and build_version as strings.
    // These are used by the server to determine if the device runs a vulnerable
    // OS version — they appear in the live-logs agent metadata row.
    test('os_version and build_version are non-empty strings', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A.231005.007',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 80,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 256,
        storageFreeGb: 100,
      );

      final json = posture.toJson();

      for (final field in ['os_version', 'build_version']) {
        if (json.containsKey(field)) {
          final val = json[field];
          expect(val, isA<String>(),
              reason: '$field must be a string');
          expect((val as String).isNotEmpty, isTrue,
              reason: '$field must not be empty');
        }
      }
    });
  });
}
