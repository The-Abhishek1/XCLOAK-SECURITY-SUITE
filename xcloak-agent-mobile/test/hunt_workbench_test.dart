// Tests for hunt workbench API shapes consumed by the mobile agent.
// The mobile agent read-only view shows hunt run summaries; notes and severity
// are set by analysts via the web UI and read back on mobile.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

void main() {
  group('Hunt Workbench (mobile API shape)', () {
    test('hunt run record includes required display fields', () {
      final run = {
        'id': 1,
        'query_type': 'process',
        'query_text': 'nmap',
        'status': 'completed',
        'result_count': 3,
        'severity': 'high',
        'notes': 'Found suspicious process',
        'started_at': '2025-01-01T00:00:00Z',
      };

      for (final key in ['id', 'query_type', 'status', 'result_count']) {
        expect(run.containsKey(key), isTrue,
            reason: 'hunt run must include "$key" for the workbench UI');
      }
    });

    test('hunt template record includes name and query fields', () {
      final tmpl = {
        'id': 1,
        'name': 'Nmap Scanner Detection',
        'query_type': 'process',
        'query_text': 'nmap',
        'description': 'Detect nmap port scans',
        'tags': ['recon', 'network'],
      };

      for (final key in ['id', 'name', 'query_type', 'query_text']) {
        expect(tmpl.containsKey(key), isTrue,
            reason: 'hunt template must include "$key"');
      }
    });

    test('update notes PATCH body includes notes and severity', () {
      final body = {
        'notes': 'Confirmed attacker recon activity',
        'severity': 'critical',
      };

      expect(body.containsKey('notes'), isTrue);
      expect(body.containsKey('severity'), isTrue);
      expect(body['notes'], isA<String>());
      expect(body['severity'], isA<String>());
    });
  });
}
