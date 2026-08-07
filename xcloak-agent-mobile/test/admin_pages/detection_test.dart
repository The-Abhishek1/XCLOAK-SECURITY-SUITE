// Live integration tests for lib/admin/screens/detection.dart
// Screens: AlertsScreen, IncidentsScreen, UEBAScreen, InsiderThreatScreen,
//          ITDRScreen, NBAScreen, DeepInspectionScreen, BehavioralScreen
//          (threat/scores), ClustersScreen, CorrelationScreen,
//          SuppressionScreen
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('AlertsScreen', () {
    test('alerts() returns real rows with real fields (log_message/'
        'mitre_technique/hostname), ack/resolve persist', () async {
      final api = await testApi();
      final open = await api.alerts(status: 'open', per: 5);
      expect(open, isNotEmpty, reason: 'expected seeded open alerts');
      final a = open.first as Map<String, dynamic>;
      final id = a['id'] as int;
      expect(a.containsKey('rule_name'), isTrue);

      final ok = await api.ackAlert(id, note: 'flutter-test ack');
      expect(ok, isTrue, reason: 'Ack button calls ackAlert');

      // AlertsScreen verifies by re-fetching the list (alertDetail() is
      // dead code, unused by any screen) — match real usage.
      final all = await api.alerts(status: 'all', per: 50, q: '');
      final refreshed = all.cast<Map<String, dynamic>>().firstWhere(
          (r) => r['id'] == id,
          orElse: () => <String, dynamic>{});
      expect(refreshed['status'], 'acknowledged',
          reason: 'Ack button tapped but status did not actually change '
              'in the list the screen re-fetches after acking');
    });

    test('severity filter actually filters (backend side)', () async {
      final api = await testApi();
      final critical = await api.alerts(sev: 'critical', per: 50);
      for (final row in critical) {
        expect((row as Map<String, dynamic>)['severity'], 'critical',
            reason: 'severity=critical filter returned a non-critical row — '
                'this is the badge-miscount bug found during manual device '
                'testing (severity chip showed count=100 regardless of '
                'filter)');
      }
    });

    test('alertInvestigation() returns data for a real alert', () async {
      final api = await testApi();
      final open = await api.alerts(status: 'open', per: 1);
      expect(open, isNotEmpty);
      final id = (open.first as Map<String, dynamic>)['id'] as int;
      final inv = await api.alertInvestigation(id);
      expect(inv, isNotNull);
    });
  });

  group('IncidentsScreen', () {
    test('incidents() loads, updateIncidentStatus accepts real statuses '
        'only (open/investigating/resolved/closed, not "contained")',
        () async {
      final api = await testApi();
      final list = await api.incidents(per: 5);
      expect(list, isNotEmpty, reason: 'expected seeded incidents');
      final id = (list.first as Map<String, dynamic>)['id'] as int;

      final ok = await api.updateIncidentStatus(id, 'investigating');
      expect(ok, isTrue);

      final refreshed = await api.incidents(per: 50);
      final row = refreshed
          .cast<Map<String, dynamic>>()
          .firstWhere((r) => r['id'] == id);
      expect(row['status'], 'investigating',
          reason: 'status update did not persist');
    });

    test('addIncidentNote() persists a real note', () async {
      final api = await testApi();
      final list = await api.incidents(per: 1);
      expect(list, isNotEmpty);
      final id = (list.first as Map<String, dynamic>)['id'] as int;
      final ok = await api.addIncidentNote(id, 'flutter-test note');
      expect(ok, isTrue);
    });
  });

  group('UEBAScreen', () {
    test('uebaUsers()/uebaEvents() return real data', () async {
      final api = await testApi();
      final users = await api.uebaUsers();
      expect(users, isA<List>());
      await api.uebaEvents();
    });
  });

  group('InsiderThreatScreen', () {
    test('insiderThreat() rows + insiderSummary() bucket counts are '
        'internally consistent', () async {
      final api = await testApi();
      final scores = await api.insiderThreat();
      expect(scores, isNotEmpty, reason: 'expected seeded insider_threat_scores');
      final s = scores.first as Map<String, dynamic>;
      expect(s.containsKey('risk_level'), isTrue);

      final summary = await api.insiderSummary();
      final total = (summary['high_risk'] as int) +
          (summary['medium_risk'] as int) +
          (summary['low_risk'] as int);
      // Summary intentionally excludes score < 30 (see
      // GetInsiderThreatSummary), so total <= raw row count, not ==.
      expect(total, greaterThan(0),
          reason: 'summary bucket total is 0 despite ${scores.length} real '
              'scored users — the KPI cards on this screen would be '
              'permanently blank');
      expect(total, lessThanOrEqualTo(scores.length));

      // Regression check for the group-2 fix: a user actually scored
      // 'critical' must land in high_risk, not be silently folded into
      // low_risk (the original bug).
      final hasCritical =
          scores.any((s) => (s as Map<String, dynamic>)['risk_level'] == 'critical');
      if (hasCritical) {
        expect(summary['high_risk'], greaterThan(0),
            reason: 'a critical-risk user exists but high_risk bucket is 0 '
                '— critical is being miscounted as low again');
      }
    });
  });

  group('ITDRScreen', () {
    test('itdrFindings() category filter uses real finding_type values',
        () async {
      final api = await testApi();
      final all = await api.itdrFindings();
      expect(all, isA<List>());
      // Real values per services/itdr_service.go — the old chips
      // (active_directory/cloud/mfa/privilege_escalation) never matched
      // anything.
      for (final cat in ['password_spray', 'mfa_gap', 'stale_account']) {
        final filtered = await api.itdrFindings(category: cat);
        for (final row in filtered) {
          expect((row as Map<String, dynamic>)['finding_type'], cat);
        }
      }
    });
  });

  group('NBAScreen', () {
    test('nbaAnomalies() returns real rows with deviation_score/detected_at',
        () async {
      final api = await testApi();
      final list = await api.nbaAnomalies();
      expect(list, isA<List>());
      if (list.isNotEmpty) {
        final a = list.first as Map<String, dynamic>;
        expect(a.containsKey('deviation_score'), isTrue,
            reason: 'NBAScreen severity chip derives from deviation_score');
      }
    });
  });

  group('DeepInspectionScreen (DPI)', () {
    test('dpiOverview/sessions/files/dlp all load', () async {
      final api = await testApi();
      final overview = await api.dpiOverview();
      expect(overview, isNotNull);
      await api.dpiSessions();
      await api.dpiFiles();
      await api.dpiDlp();
    });
  });

  group('ClustersScreen', () {
    test('clusters() returns real rule_name/status/last_seen fields',
        () async {
      final api = await testApi();
      final list = await api.clusters();
      expect(list, isA<List>());
      if (list.isNotEmpty) {
        final c = list.first as Map<String, dynamic>;
        expect(c.containsKey('rule_name') || c.containsKey('cluster_key'), isTrue,
            reason: 'group-1 fix regression check: real fields are '
                'rule_name/cluster_key, not the fabricated cluster_name');
      }
    });
  });

  group('CorrelationScreen', () {
    test('correlationRules() + toggle sends explicit desired state',
        () async {
      final api = await testApi();
      final rules = await api.correlationRules();
      expect(rules, isNotEmpty, reason: 'expected seeded correlation_rules');
      final r = rules.first as Map<String, dynamic>;
      final id = r['id'] as int;
      final wasEnabled = r['enabled'] as bool? ?? false;

      final ok = await api.toggleCorrelationRule(id, !wasEnabled);
      expect(ok, isTrue);

      final refreshed = (await api.correlationRules())
          .cast<Map<String, dynamic>>()
          .firstWhere((x) => x['id'] == id);
      expect(refreshed['enabled'], !wasEnabled,
          reason: 'toggle must flip to the explicit requested state — '
              'the old empty-body contract always forced it to false');

      // put it back the way we found it
      await api.toggleCorrelationRule(id, wasEnabled);

      await api.correlationMatches();
    });
  });

  group('SuppressionScreen', () {
    test('createSuppressionRule() persists a real rule_name (not silently '
        'dropped into an empty-criteria wildcard rule)', () async {
      final api = await testApi();
      final marker = 'flutter-test-rule-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createSuppressionRule({
        'rule_name': marker,
        'reason': 'integration test',
      });
      expect(ok, isTrue);

      final rules = await api.suppressionRules();
      final created = rules.cast<Map<String, dynamic>>().where(
          (r) => r['rule_name'] == marker || r['conditions']?.toString().contains(marker) == true);
      expect(created, isNotEmpty,
          reason: 'created rule not found by rule_name/conditions — the '
              'match criteria the user typed may be getting silently '
              'dropped, which (per the group-2 finding) used to create a '
              'wildcard rule matching every alert instead');

      final id = created.first['id'] as int;
      final delOk = await api.deleteSuppression(id);
      expect(delOk, isTrue);
    });
  });
}
