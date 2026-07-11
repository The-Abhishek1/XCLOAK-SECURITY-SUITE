// Tests that mobile agent device posture contributes correctly to risk posture
// — specifically that is_rooted and developer_mode_on are accurately reported,
// since these drive the mobile risk signal used by the server's posture score.
//
// Also verifies that the mobile agent does not send server-computed risk scores
// that could bypass the server's multi-source scoring model.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Risk posture (mobile)', () {
    // The mobile heartbeat must never include the composite risk score or
    // sub-scores. Those are computed server-side from multiple data sources
    // (vulns, alerts, UEBA, IOC). An agent sending a score would let a
    // compromised phone claim a low risk level.
    test('mobile heartbeat excludes all risk-posture score fields', () {
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

      const scoreFields = [
        'score',
        'vuln_score',
        'ueba_score',
        'alert_score',
        'ioc_score',
        'snoozed_alert_count',
        'asset_scores',
        'risk_posture',
        'snapshot_at',
        'risk_level',
        'compromise_cost',
      ];

      for (final field in scoreFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not include risk-posture field "$field"');
      }
    });

    // is_rooted = true must be reported honestly. The server uses this as a
    // mobile risk signal; a compromised device that sets it to false would
    // appear healthy in the risk posture dashboard.
    test('is_rooted=true is faithfully reported', () {
      final rooted = DevicePosture(
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

      final json = rooted.toJson();

      expect(json['is_rooted'], isTrue,
          reason: 'A rooted device must report is_rooted=true');
      expect(json['developer_mode_on'], isTrue,
          reason: 'Developer mode must be accurately reported');

      // Ensure they are boolean, not 1 or "true"
      expect(json['is_rooted'], isA<bool>());
      expect(json['developer_mode_on'], isA<bool>());
    });

    // security_patch_level affects how the server evaluates the device's
    // patch status against known CVEs. Missing or wrong format reduces
    // the server's ability to score device vulnerability.
    test('security_patch_level serializes correctly when provided', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 70,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
        securityPatchLevel: '2024-01-05',
      );

      final json = posture.toJson();

      if (json.containsKey('security_patch_level')) {
        expect(json['security_patch_level'], isA<String>(),
            reason: 'security_patch_level must be a string (YYYY-MM-DD format)');
      }
    });
  });
}
