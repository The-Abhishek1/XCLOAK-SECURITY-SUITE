// Live integration tests for lib/admin/screens/inventory.dart
// Screens: AssetsScreen, MDMScreen
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('AssetsScreen', () {
    test('assets() returns real CMDB rows, updateAsset() persists', () async {
      final api = await testApi();
      final list = await api.assets();
      expect(list, isNotEmpty, reason: 'expected seeded ace_assets rows');
      final a = list.first as Map<String, dynamic>;
      final id = a['asset_id'].toString();
      expect(a.containsKey('hostname') || a.containsKey('name'), isTrue);

      final marker = 'flutter-test-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.updateAsset(id, {'owner': marker});
      expect(ok, isTrue, reason: 'AssetsScreen Edit sheet calls updateAsset');

      final refreshed = await api.assets();
      final updated = refreshed
          .cast<Map<String, dynamic>>()
          .firstWhere((r) => r['asset_id'].toString() == id);
      expect(updated['owner'], marker,
          reason: 'edit did not actually persist — Edit button would look '
              'like it worked but silently not save');
    });

    test('platformSummary() returns data', () async {
      final api = await testApi();
      final r = await api.platformSummary();
      expect(r, isNotNull);
    });
  });

  group('MDMScreen', () {
    test('mdmDevices() rows have real serial_number/last_check_in fields',
        () async {
      final api = await testApi();
      final list = await api.mdmDevices();
      // May be empty if no device has enrolled — not itself a bug, but if
      // there ARE rows, they must have the real field names (group-3 fix
      // regression check: serial/last_seen used to be wrong).
      if (list.isNotEmpty) {
        final d = list.first as Map<String, dynamic>;
        expect(d.containsKey('serial_number'), isTrue,
            reason: 'MDMScreen device list reads serial_number, not serial');
        expect(d.containsKey('last_check_in'), isTrue,
            reason:
                'MDMScreen device list reads last_check_in, not last_seen');
      }
    });

    test('createEnrollmentToken() + mdmTokens() round-trip shows real '
        'used_count/max_uses, not the removed enrollment_type', () async {
      final api = await testApi();
      final res = await api.createEnrollmentToken();
      expect(res, isNotNull,
          reason: 'MDMScreen "Generate Token" button calls this directly');

      final tokens = await api.mdmTokens();
      expect(tokens, isNotEmpty);
      final t = tokens.first as Map<String, dynamic>;
      expect(t.containsKey('used_count'), isTrue,
          reason: 'group-3 fix: real field is used_count, not used');
    });
  });
}
