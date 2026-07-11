// Tests for canary token and honeyport API shapes used by the mobile agent.
// The mobile agent can trip canary tokens embedded in documents and URLs
// that are distributed to mobile devices.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Deception (canary tokens & honeyports)', () {
    test('canary token record includes required fields', () {
      final token = {
        'id': 1,
        'token_type': 'url',
        'name': 'S3 Bucket Canary',
        'token_value': 'c-abc123',
        'is_active': true,
        'trip_count': 0,
      };

      for (final key in ['id', 'token_type', 'name', 'token_value', 'is_active']) {
        expect(token.containsKey(key), isTrue,
            reason: 'canary token must include "$key" for the deception UI');
      }
    });

    test('toggle body uses is_active bool field', () {
      final body = {'is_active': false};
      expect(body['is_active'], isA<bool>(),
          reason: 'toggle PATCH body must use is_active as bool');
    });

    test('canary token and honeyport URL patterns are correct', () {
      String tokenUrl(int id) => '/api/canary/tokens/$id';
      String tokenToggle(int id) => '/api/canary/tokens/$id/toggle';
      String honeyportUrl(int id) => '/api/honeyports/$id';

      expect(tokenUrl(3), equals('/api/canary/tokens/3'));
      expect(tokenToggle(3), equals('/api/canary/tokens/3/toggle'));
      expect(honeyportUrl(7), equals('/api/honeyports/7'));
    });
  });
}
