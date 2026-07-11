// Tests that the mobile agent's log submission payload is compatible with the
// backend log-source ingest contract. The mobile agent submits logs via the
// agent check-in endpoint (not the HTTP log-source API key flow).
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Log sources (mobile agent)', () {
    // Mobile agents authenticate with an enrollment token, not an HTTP log-source
    // API key. Verify that no api_key field leaks into the posture payload.
    test('mobile posture payload excludes api_key fields', () {
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

      const authFields = [
        'api_key', 'x_api_key', 'key', 'token',
        'authorization', 'bearer',
      ];

      for (final field in authFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile posture must not include auth field "$field" — '
                'agent uses enrollment token, not log-source API key');
      }
    });

    // The mobile agent submits network_type as a string (e.g. "wifi", "lte").
    // The backend log-source event routing uses this for display only — it must
    // not be confused with the log_source routing key.
    test('network_type is present and is a string', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();

      expect(json.containsKey('network_type'), isTrue,
          reason: 'network_type must be present in mobile posture');
      expect(json['network_type'], isA<String>(),
          reason: 'network_type must be a string');
    });

    // Log-source wildcard routing (null ip_address) is a backend concern.
    // The mobile agent must not send an ip_address field that could interfere
    // with syslog source matching on the server.
    test('mobile posture excludes ip_address field', () {
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

      expect(json.containsKey('ip_address'), isFalse,
          reason:
              'Mobile agent must not send ip_address — log-source IP routing is server-controlled');
    });
  });
}
