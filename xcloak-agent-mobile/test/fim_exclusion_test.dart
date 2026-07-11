// Tests that verify the mobile agent correctly handles file-integrity-related
// payload contracts. Android does not run FIM scans (no access to system
// files), but the heartbeat does report security_patch and storage metrics
// that partially overlap with desktop FIM concerns.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('FIM / security-posture payload contracts (mobile)', () {
    // The mobile agent NEVER sends fim-related keys in its heartbeat.
    // Backend FIM handlers expect only desktop agents; receiving fim_* keys
    // from a mobile device would indicate a payload schema bug.
    test('mobile heartbeat does not include FIM-specific keys', () {
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

      // These keys belong to the desktop FIM scan payload, not mobile.
      const desktopFIMKeys = [
        'file_path',
        'sha256_hash',
        'old_hash',
        'new_hash',
        'old_mode',
        'new_mode',
        'change_type',
        'fim_baseline',
        'file_mode',
        'file_uid',
        'file_gid',
      ];

      for (final key in desktopFIMKeys) {
        expect(json.containsKey(key), isFalse,
            reason: 'Mobile heartbeat must not include desktop FIM key "$key"');
      }
    });

    // The mobile agent DOES report security_patch, which is the closest
    // equivalent to file integrity on Android — the OS patch level tells
    // analysts whether a device is running a known-vulnerable kernel.
    test('security_patch_level is included when set', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A.240105.004',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 90,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 64,
        storageFreeGb: 30,
        securityPatchLevel: '2024-01-05',
      );

      final json = posture.toJson();

      expect(json.containsKey('security_patch_level'), isTrue,
          reason: 'security_patch_level missing from heartbeat — backend cannot assess patch freshness');
      expect(json['security_patch_level'], equals('2024-01-05'));
    });

    // A rooted device is the Android equivalent of a host where file-system
    // integrity cannot be assumed — the detection engine relies on this flag
    // to raise an alert analogous to a FIM violation.
    test('is_rooted flag is present and boolean', () {
      for (final rooted in [true, false]) {
        final posture = DevicePosture(
          osVersion: 'Android 13',
          buildVersion: 'TP1A',
          isRooted: rooted,
          developerModeOn: false,
          batteryLevel: 50,
          batteryCharging: false,
          networkType: 'lte',
          storageTotalGb: 32,
          storageFreeGb: 10,
        );

        final json = posture.toJson();
        expect(json.containsKey('is_rooted'), isTrue,
            reason: 'is_rooted missing from DevicePosture.toJson()');
        expect(json['is_rooted'], isA<bool>(),
            reason: 'is_rooted must be bool (not string/int) for backend alert logic');
        expect(json['is_rooted'], equals(rooted));
      }
    });

    // Storage_free_gb is analogous to FIM coverage gap: if disk is nearly
    // full, the mobile agent may have silently skipped scans or log uploads.
    // The backend can use this to flag agents whose data may be incomplete.
    test('storage fields are non-negative numbers', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 70,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 8,
      );

      final json = posture.toJson();

      final freeGb  = json['storage_free_gb']  as num;
      final totalGb = json['storage_total_gb'] as num;

      expect(freeGb,  greaterThanOrEqualTo(0));
      expect(totalGb, greaterThan(0));
      expect(freeGb,  lessThanOrEqualTo(totalGb),
          reason: 'free storage cannot exceed total storage');
    });
  });
}
