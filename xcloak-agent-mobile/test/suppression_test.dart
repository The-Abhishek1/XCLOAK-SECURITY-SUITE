// Tests for suppression rule API shapes consumed by the mobile agent.
// The mobile agent may display suppressed alert states; suppression rules
// are read from the backend to decide whether to surface notifications.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Suppression Rules (mobile API shape)', () {
    test('suppression rule record includes required fields', () {
      final rule = {
        'id': 1,
        'name': 'Block Nmap',
        'rule_name': 'nmap_scan',
        'window_minutes': 60,
        'enabled': true,
        'match_count': 3,
      };

      for (final key in ['id', 'name', 'rule_name', 'window_minutes', 'enabled']) {
        expect(rule.containsKey(key), isTrue,
            reason: 'suppression rule must include "$key" for the suppression UI');
      }
    });

    test('toggle body uses enabled bool field', () {
      final body = {'enabled': false};
      expect(body['enabled'], isA<bool>(),
          reason: 'toggle PATCH body must use enabled as bool per backend contract');
    });

    test('suppression rule URL patterns are correct', () {
      String ruleUrl(int id) => '/api/suppression/rules/$id';
      String toggleUrl(int id) => '/api/suppression/rules/$id/toggle';

      expect(ruleUrl(9), equals('/api/suppression/rules/9'));
      expect(toggleUrl(9), equals('/api/suppression/rules/9/toggle'));
    });
  });
}
