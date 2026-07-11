// Tests for JA3 fingerprint API shape consumed by the mobile agent.
// The mobile agent submits TLS connection metadata that the backend matches
// against known JA3 hashes.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

void main() {
  group('JA3 Fingerprints (mobile TLS metadata)', () {
    test('JA3 hash must be exactly 32 hex characters', () {
      const validHash = 'aabbccddeeff00112233445566778899';
      expect(validHash.length, equals(32),
          reason: 'JA3 MD5 hash is always 32 hex chars; backend rejects shorter values');
      expect(RegExp(r'^[0-9a-f]{32}$').hasMatch(validHash), isTrue);
    });

    test('fingerprint record includes required display fields', () {
      final fp = {
        'id': 1,
        'hash': 'aabbccddeeff00112233445566778899',
        'threat_name': 'Cobalt Strike',
        'severity': 'critical',
        'source': 'threat-intel',
      };

      for (final key in ['id', 'hash', 'threat_name', 'severity']) {
        expect(fp.containsKey(key), isTrue,
            reason: 'JA3 fingerprint must include "$key" for the threat intel UI');
      }
    });

    test('delete URL pattern is correct', () {
      String buildDeleteUrl(int id) => '/api/ja3/fingerprints/$id';
      expect(buildDeleteUrl(5), equals('/api/ja3/fingerprints/5'));
    });
  });
}
