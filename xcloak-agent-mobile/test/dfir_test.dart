// Tests for DFIR (digital forensics & incident response) API shapes used by
// the mobile agent. The mobile agent can trigger forensic collection on a
// device and report artifact data back to the backend.
//
// Run with: flutter test

import 'package:flutter_test/flutter_test.dart';

void main() {
  group('DFIR / Forensic Collections (mobile)', () {
    test('forensic collection record includes required status fields', () {
      final col = {
        'id': 1,
        'label': 'Incident 7 Collection',
        'status': 'completed',
        'artifact_types': ['processes', 'connections'],
        'triggered_by': 'soc-analyst',
      };

      for (final key in ['id', 'label', 'status', 'artifact_types']) {
        expect(col.containsKey(key), isTrue,
            reason: 'forensic collection must include "$key" for the DFIR UI');
      }
    });

    test('trigger collection payload uses artifact_types as a list', () {
      final payload = {
        'agent_id': 1,
        'artifact_types': ['processes', 'connections', 'file_hashes'],
      };

      expect(payload['artifact_types'], isA<List>(),
          reason: 'artifact_types must be a list — single string is rejected by backend');
      expect((payload['artifact_types'] as List).isNotEmpty, isTrue);
    });

    test('DFIR URL patterns are correct', () {
      String artifactsUrl(int id) => '/api/dfir/collections/$id/artifacts';
      String timelineUrl(int incidentId) =>
          '/api/dfir/incidents/$incidentId/timeline';

      expect(artifactsUrl(4), equals('/api/dfir/collections/4/artifacts'));
      expect(timelineUrl(7), equals('/api/dfir/incidents/7/timeline'));
    });
  });
}
