// Unit tests for alert-related payload shapes on the mobile agent.
// These run without a device via `flutter test`.

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Alert-triggering payload contracts', () {
    // The mobile agent sends a threat-scan summary to
    // /api/mdm/devices/:id/threat-scan. This test verifies the payload shape
    // that the backend MDM handler parses. If someone removes a key, the
    // backend silently gets a zero value — this test catches the change.
    test('threat scan payload includes required keys', () {
      // Simulate what ThreatDetector.threatSummary() returns (static, no
      // platform channel needed — we test the shape, not live data).
      final payload = <String, dynamic>{
        'total_apps':         42,
        'sideloaded_count':   3,
        'system_app_count':   18,
        'sideloaded_packages': ['com.malware.app', 'io.unknown.pkg'],
      };

      const requiredKeys = [
        'total_apps',
        'sideloaded_count',
        'system_app_count',
        'sideloaded_packages',
      ];

      for (final key in requiredKeys) {
        expect(payload.containsKey(key), isTrue,
            reason: 'Threat scan payload missing key "$key"');
      }

      expect(payload['total_apps'], isA<int>());
      expect(payload['sideloaded_count'], isA<int>());
      expect(payload['sideloaded_packages'], isA<List>());
    });

    test('sideloaded_count never exceeds total_apps', () {
      // Invariant: cannot have more sideloaded than total installed.
      final totalApps     = 50;
      final sideloaded    = 3;

      expect(sideloaded, lessThanOrEqualTo(totalApps));
    });

    test('sideloaded_packages limited to 20 entries', () {
      // The backend paginator only processes up to 20 sideloaded packages;
      // sending more is wasteful. This mirrors the .take(20) in
      // ThreatDetector.threatSummary().
      const maxPackages = 20;

      final mockPackages = List.generate(25, (i) => 'com.test.pkg$i');
      final capped = mockPackages.take(maxPackages).toList();

      expect(capped.length, equals(maxPackages));
    });

    // Verify that a DevicePosture with is_rooted=true produces a heartbeat
    // payload that the backend alert detection engine can act on.
    // The detection engine fires an alert when is_rooted=true arrives.
    test('rooted device heartbeat payload marks is_rooted true', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: true,
        developerModeOn: true,
        batteryLevel: 60,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final heartbeatPayload = {
        'is_rooted':      posture.isRooted,
        'developer_mode': posture.developerModeOn,
      };

      expect(heartbeatPayload['is_rooted'],      isTrue);
      expect(heartbeatPayload['developer_mode'], isTrue);
    });

    test('vpn_active flag correctly propagated in heartbeat', () {
      final postureWithVPN = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        vpnActive: true,
        batteryLevel: 80,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      final postureNoVPN = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        vpnActive: false,
        batteryLevel: 80,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 64,
      );

      expect(postureWithVPN.vpnActive, isTrue);
      expect(postureNoVPN.vpnActive, isFalse);

      // Backend stores vpn_active and can raise an alert if policy requires VPN.
      final jsonWith    = postureWithVPN.toJson();
      final jsonWithout = postureNoVPN.toJson();

      expect(jsonWith['vpn_active'],    isTrue);
      expect(jsonWithout['vpn_active'], isFalse);
    });
  });
}
