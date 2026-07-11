// Tests that mobile agent payloads do not carry dashboard-aggregated fields.
// Threat score, anomaly score, open/snoozed alert counts, MTTR/MTTD — these
// are all server-side computations. A compromised device sending them would
// let the endpoint manipulate what SOC operators see on the dashboard.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Dashboard exclusion (mobile)', () {
    // The heartbeat payload the mobile agent sends must NEVER include fields
    // that belong to the server-side dashboard aggregation layer.
    test('mobile heartbeat excludes all dashboard-aggregated fields', () {
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

      const dashboardAggregates = [
        'threat_score',
        'anomaly_score',
        'compliance_score',
        'alert_velocity_1h',
        'open_alerts',
        'snoozed_alerts',
        'critical_alerts',
        'mttr',
        'mttd',
        'ioc_hits',
        'mitre_tactics',
        'rule_health',
        'top_rules',
        'top_agents',
      ];

      for (final field in dashboardAggregates) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not include dashboard-aggregate field "$field"');
      }
    });

    // The payload must contain the posture fields the MDM check-in endpoint
    // actually reads. Missing fields would make the agent appear unresponsive.
    test('mobile heartbeat contains all required posture fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 10,
      );

      final json = posture.toJson();

      const required = [
        'battery_level',
        'battery_charging',
        'network_type',
        'storage_total_gb',
        'storage_free_gb',
        'is_rooted',
        'developer_mode_on',
      ];

      for (final key in required) {
        expect(json.containsKey(key), isTrue,
            reason: 'Mobile posture payload missing required field "$key"');
      }
    });

    // battery_level must be a number (int or double), not a string.
    // A string value would make the server's trend data silently show 0.
    test('battery_level is numeric', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 45,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 32,
        storageFreeGb: 8,
      );

      final json = posture.toJson();

      expect(json['battery_level'], isA<num>(),
          reason: 'battery_level must be numeric, not a string');
      expect(json['battery_level'], equals(45));
    });
  });
}
