// Tests that the mobile agent does not include Elasticsearch DSL or query fields
// in its heartbeat. The ES query interface is analyst-facing; agents only submit
// raw posture data and log entries via their own ingest endpoints.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

import 'package:xcloak_agent/models/device_posture.dart';

void main() {
  group('Elastic query (mobile exclusion)', () {
    // The mobile heartbeat must not contain any ES query DSL fields.
    // An agent that sends 'query' or 'index' fields could be mistaken for
    // an ES query payload or pollute the log index routing logic.
    test('mobile heartbeat excludes all ES DSL fields', () {
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

      const esDSLFields = [
        'dsl', 'query', 'index', '_index', 'bool', 'must', 'should',
        'filter', 'aggs', 'aggregations', 'match_all', 'match_phrase',
        'size', 'from', 'sort',
      ];

      for (final field in esDSLFields) {
        expect(json.containsKey(field), isFalse,
            reason:
                'Mobile heartbeat must not include ES DSL field "$field"');
      }
    });

    // tenant_id must never be set by the mobile agent. The server derives it
    // from the agent's authenticated session — an agent sending tenant_id could
    // attempt to redirect its logs to another tenant's ES index.
    test('mobile heartbeat excludes tenant_id', () {
      final posture = DevicePosture(
        osVersion: 'Android 13',
        buildVersion: 'TP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 55,
        batteryCharging: false,
        networkType: 'lte',
        storageTotalGb: 64,
        storageFreeGb: 20,
      );

      final json = posture.toJson();

      expect(json.containsKey('tenant_id'), isFalse,
          reason: 'Mobile agent must not include tenant_id — set by server from auth context');
    });

    // The mobile posture payload should only contain fields the server
    // expects. Any extra fields are silently ignored but add payload bloat
    // and could shadow server-controlled fields if ES field names clash.
    test('posture payload contains only expected posture fields', () {
      final posture = DevicePosture(
        osVersion: 'Android 14',
        buildVersion: 'UP1A',
        isRooted: false,
        developerModeOn: false,
        batteryLevel: 70,
        batteryCharging: true,
        networkType: 'wifi',
        storageTotalGb: 256,
        storageFreeGb: 128,
      );

      final json = posture.toJson();

      const knownPostureFields = {
        'os_version', 'build_version', 'security_patch_level',
        'android_sdk_version', 'manufacturer', 'hardware',
        'is_encrypted', 'has_passcode', 'passcode_compliant',
        'biometric_enrolled', 'is_rooted', 'developer_mode_on',
        'usb_debugging_enabled', 'unknown_sources_enabled',
        'vpn_active', 'battery_level', 'battery_charging',
        'network_type', 'wifi_ssid', 'storage_total_gb', 'storage_free_gb',
        'ram_total_mb', 'push_token',
      };

      for (final key in json.keys) {
        expect(knownPostureFields.contains(key), isTrue,
            reason: 'Unexpected posture field "$key" — not in known field set');
      }
    });
  });
}
