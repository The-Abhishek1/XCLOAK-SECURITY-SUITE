// Tests that mobile agent heartbeat payloads do not carry network-map
// topology fields. Network map is built server-side from endpoint_connections
// and connect_events. A mobile device sending those fields would let a
// compromised phone influence what the SOC sees on the network map.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Network map exclusion (mobile)', () {
    // Mobile heartbeat must NOT include fields from the network-map data model.
    test('mobile heartbeat excludes all network-map topology fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 72,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 128,
        storageFreeGb: 48,
      );

      final json = posture.toJson();

      // These are all server-built network-map fields. The agent must never send
      // them — they can only be computed from connection streams on the server.
      const networkMapFields = [
        'nodes',
        'edges',
        'summary',
        'generated_at',
        'risk_score',
        'risk_level',
        'is_ioc',
        'ioc_severity',
        'zone',
        'edge_type',
        'port_sensitivity',
        'process',
        'count',
        'alert_count',
      ];

      for (final field in networkMapFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not include network-map field "$field"');
      }
    });

    // network_type is a posture field (wifi, lte, none), NOT the same as the
    // network-map zone (internal, dmz, external). Verify it serializes correctly.
    test('network_type is posture-level, not topology-level', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 50,
        batteryCharging: true,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();

      expect(json.containsKey('network_type'), isTrue);
      expect(json['network_type'], equals('lte'));

      // Must NOT be confused with topology zone
      expect(json.containsKey('zone'), isFalse);
      expect(json.containsKey('edge_type'), isFalse);
    });

    // vpn_active is an optional posture field — distinct from is_proxy in the
    // network-map IP enrichment. Verify it doesn't bleed into map fields.
    test('vpn_active is a posture field, not an IP enrichment field', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 30,
        batteryCharging: false,
        networkType: 'wifi',
        storageTotalGb: 32,
        storageFreeGb: 10,
        vpnActive: true,
      );

      final json = posture.toJson();

      // vpn_active is the posture key; is_proxy belongs to IPEnrichment only
      expect(json.containsKey('vpn_active'), isTrue);
      expect(json['vpn_active'], isTrue);
      expect(json.containsKey('is_proxy'), isFalse,
          reason: 'is_proxy is an IP-enrichment field, not a device posture field');
    });
  });
}
