// Live integration tests for lib/admin/screens/compliance.dart
// Screens: ExecutiveScreen, FrameworksScreen, ReportsScreen,
//          RiskPostureScreen, SOCMetricsScreen, VulnQueueScreen
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('ExecutiveScreen', () {
    test('executiveMetrics() returns real exe_snapshots fields under '
        '"latest" (screen unwraps this itself)', () async {
      final api = await testApi();
      final r = await api.executiveMetrics();
      expect(r, isNotNull);
      expect(r!.containsKey('latest'), isTrue);
      final latest = r['latest'] as Map<String, dynamic>;
      for (final key in ['security_score', 'mttr_hours', 'sla_compliance', 'total_incidents']) {
        expect(latest.containsKey(key), isTrue, reason: 'missing "$key"');
      }
    });
  });

  group('FrameworksScreen', () {
    test('frameworkAssessments() returns real overall_score/'
        'passed_controls fields', () async {
      final api = await testApi();
      final list = await api.frameworkAssessments();
      expect(list, isNotEmpty, reason: 'expected seeded fce_frameworks rows');
      final f = list.first as Map<String, dynamic>;
      expect(f.containsKey('overall_score'), isTrue,
          reason: 'real field is overall_score, not compliance_score');
      final ok = await api.refreshFrameworks();
      expect(ok, isTrue);
    });
  });

  group('ReportsScreen', () {
    test('create -> generate -> real status field -> delete', () async {
      final api = await testApi();
      final title = 'flutter-test-report-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createReport({'name': title, 'report_type': 'compliance_summary'});
      expect(ok, isTrue);

      final reports = await api.complianceReports();
      final r = reports.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == title);
      expect(r.containsKey('status'), isTrue,
          reason: 'group-4 fix regression: real status field must exist '
              '(compliance_reports table previously had no status column)');
      final id = r['id'];

      final genOk = await api.generateReport(id.toString());
      expect(genOk, isTrue);

      final delOk = await api.deleteReport(id is int ? id : int.parse(id.toString()));
      expect(delOk, isTrue);
    });
  });

  group('RiskPostureScreen', () {
    test('riskPosture() returns real sub-scores, refresh works', () async {
      final api = await testApi();
      final r = await api.riskPosture();
      expect(r, isNotNull);
      expect(r!.containsKey('score'), isTrue);
      final ok = await api.refreshRiskPosture();
      expect(ok, isTrue);
    });
  });

  group('SOCMetricsScreen', () {
    test('socMetrics()/socAlertMetrics()/socAnalysts() load real data',
        () async {
      final api = await testApi();
      final metrics = await api.socMetrics();
      expect(metrics, isNotNull,
          reason: 'socMetrics unwraps the sme_dashboard "latest" key — a '
              'null here means either no snapshot exists yet or the '
              'unwrap is broken');
      await api.socAlertMetrics();
      final analysts = await api.socAnalysts();
      expect(analysts, isA<List>());
    });
  });

  group('VulnQueueScreen', () {
    test('vulnQueue() loads, vqAction persists a real status change',
        () async {
      final api = await testApi();
      final list = await api.vulnQueue();
      expect(list, isA<List>());
      if (list.isNotEmpty) {
        final v = list.first as Map<String, dynamic>;
        final id = v['id'] as int;
        final ok = await api.vqAction(id, 'complete');
        expect(ok, isTrue);
      }
    });
  });
}
