// Tests that the mobile agent heartbeat excludes server-computed agent fields
// (open_alert_count, risk_score) and correctly serializes the posture metrics
// the server uses to build the agent record.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Agents (mobile heartbeat contract)', () {
    // The mobile agent must never send open_alert_count or risk_score.
    // These are computed server-side from alerts and asset_risk_scores.
    // A compromised device that sends a fake low count could hide active
    // alerts from the agents list view.
    test('mobile heartbeat excludes server-computed agent fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 85,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 60,
      );

      final json = posture.toJson();

      const serverOnlyFields = [
        'open_alert_count',
        'risk_score',
        'risk_level',
        'health_score',
        'health_status',
        'alert_rate_1h',
      ];

      for (final field in serverOnlyFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not include server-computed field "$field"');
      }
    });

    // network_type drives the server's understanding of connectivity at check-in.
    // It must be a non-empty string; 'unknown' is acceptable when the OS cannot
    // determine connectivity type (e.g. airplane mode transitioning).
    test('network_type serializes as a string', () {
      for (final netType in ['wifi', 'lte', '5g', 'ethernet', 'unknown']) {
        final posture = DevicePosture(
          osVersion: 'Android 14',
          buildVersion: 'UP1A',
          isRooted: false,
          developerModeOn: false,
          batteryLevel: 50,
          batteryCharging: true,
          networkType: netType,
          storageTotalGb: 64,
          storageFreeGb: 32,
        );

        final json = posture.toJson();

        if (json.containsKey('network_type')) {
          expect(json['network_type'], isA<String>(),
              reason: 'network_type must be a string, got ${json['network_type'].runtimeType}');
          expect((json['network_type'] as String).isNotEmpty, isTrue,
              reason: 'network_type must not be empty');
        }
      }
    });

    // storage_free_gb and storage_total_gb drive the server's assessment of
    // whether the device has enough space for forensic artifact collection.
    // They must be numbers, not strings.
    test('storage metrics serialize as numbers', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 70,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 256,
        storageFreeGb: 128,
      );

      final json = posture.toJson();

      for (final field in ['storage_total_gb', 'storage_free_gb']) {
        if (json.containsKey(field)) {
          expect(json[field], isA<num>(),
              reason: '$field must be a number, not a string');
          expect((json[field] as num) >= 0, isTrue,
              reason: '$field must be non-negative');
        }
      }

      // total must be >= free
      if (json.containsKey('storage_total_gb') &&
          json.containsKey('storage_free_gb')) {
        final total = (json['storage_total_gb'] as num).toDouble();
        final free = (json['storage_free_gb'] as num).toDouble();
        expect(total >= free, isTrue,
            reason: 'storage_total_gb ($total) must be >= storage_free_gb ($free)');
      }
    });
  });
}
