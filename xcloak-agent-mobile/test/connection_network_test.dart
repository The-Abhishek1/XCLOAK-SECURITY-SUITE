// Tests for the mobile agent's network-related payload contracts.
// Mobile agents don't enumerate socket connections (no /proc access),
// but they report network_type in the heartbeat. These tests verify that:
//   1. Mobile heartbeat does NOT include desktop connection-scan fields.
//   2. network_type values are constrained to the set the backend expects.
//   3. The storage fields sent alongside network_type are consistent.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Network connection payload contracts (mobile)', () {
    // Mobile heartbeat must NOT include any desktop connection-scan fields.
    // Sending these would confuse the backend's process-binding enrichment.
    test('mobile heartbeat excludes desktop connection-scan keys', () {
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

      const desktopConnectionKeys = [
        'local_address',
        'remote_address',
        'process_name',
        'process_path',
        'pid',
        'state',
        'protocol',
        'country',
        'country_code',
        'is_proxy',
      ];

      for (final key in desktopConnectionKeys) {
        expect(json.containsKey(key), isFalse,
            reason: 'Mobile heartbeat must not include desktop connection field "$key"');
      }
    });

    // network_type must be one of the values the backend detection engine
    // recognises. An unexpected value (e.g. "4G_LTE") would silently fail
    // to match policy rules like "alert when off corporate wifi".
    test('network_type is in the allowed set', () {
      const allowedTypes = {'wifi', 'lte', '5g', 'ethernet', 'none', 'unknown', 'cellular'};

      final types = [
        'wifi',
        'lte',
        '5g',
        'ethernet',
        'none',
      ];

      for (final type in types) {
        expect(allowedTypes.contains(type), isTrue,
            reason: '"$type" is not in the backend\'s recognised network_type set');

        final posture = DevicePosture(
          osVersion: 'Android 14',
          buildVersion: 'UP1A',
          isRooted: false,
          developerModeOn: false,
          batteryLevel: 60,
          batteryCharging: false,
          networkType: type,
          storageTotalGb: 64,
          storageFreeGb: 20,
        );

        final json = posture.toJson();
        expect(json['network_type'], equals(type),
            reason: 'network_type not propagated correctly for "$type"');
      }
    });

    // VPN active should surface as a distinct flag, not an alternate
    // network_type value. This matters because the backend alert rule for
    // "user not on VPN" checks vpn_active, not network_type.
    test('vpn_active is separate from network_type', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 75,
        batteryCharging: false,
        networkType: 'wifi',
        vpnActive: true,
        storageTotalGb: 128,
        storageFreeGb: 50,
      );

      final json = posture.toJson();

      // network_type stays "wifi" — VPN doesn't replace it.
      expect(json['network_type'], equals('wifi'));
      // vpn_active is a separate boolean key.
      expect(json.containsKey('vpn_active'), isTrue,
          reason: 'vpn_active missing — backend cannot enforce VPN policy');
      expect(json['vpn_active'], isTrue);
    });

    // Verify that the payload fields are in the expected types so backend
    // JSON unmarshalling doesn't silently coerce them.
    test('network payload field types are correct', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 50,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 10,
      );

      final json = posture.toJson();

      expect(json['network_type'],    isA<String>());
      expect(json['battery_level'],   isA<int>());
      expect(json['storage_free_gb'], isA<num>());
      expect(json['storage_total_gb'],isA<num>());
      expect(json['is_rooted'],       isA<bool>());
    });
  });
}
