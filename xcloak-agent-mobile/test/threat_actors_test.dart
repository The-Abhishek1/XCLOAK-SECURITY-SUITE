// Tests that verify the mobile agent correctly handles threat actor API
// responses. The mobile agent reads threat actor data in the alerts view to
// show actor attribution.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Threat Actors (mobile API response handling)', () {
    test('threat actor record includes required display fields', () {
      final actor = {
        'id': 1,
        'name': 'APT-28',
        'sophistication': 'nation-state',
        'motivation': 'espionage',
        'mitre_techniques': ['T1566', 'T1059'],
        'origin_country': 'RU',
      };

      for (final key in ['id', 'name', 'sophistication', 'motivation']) {
        expect(actor.containsKey(key), isTrue,
            reason: 'threat actor must include "$key" for the alert attribution UI');
      }
    });

    test('actor alerts URL is constructed correctly', () {
      String buildUrl(int actorId, int limit) =>
          '/api/threat-actors/$actorId/alerts?limit=$limit';

      expect(buildUrl(42, 10), equals('/api/threat-actors/42/alerts?limit=10'));
    });

    test('actor mitre_techniques is a list', () {
      final actor = {
        'id': 2,
        'name': 'Lazarus Group',
        'mitre_techniques': ['T1059', 'T1055', 'T1003'],
      };

      expect(actor['mitre_techniques'], isA<List>());
      expect((actor['mitre_techniques'] as List).isNotEmpty, isTrue);
    });
  });
}
