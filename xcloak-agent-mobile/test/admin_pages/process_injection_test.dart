// Live integration tests for lib/admin/screens/process_injection.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('ProcessInjectionScreen', () {
    test('dashboard/processes/process-tree/injections real data', () async {
      final api = await testApi();
      final dash = await api.piDashboard();
      expect(dash, isNotNull);
      final procs = await api.piProcesses();
      expect(procs, isA<List>());
      await api.piProcessTree();
      final inj = await api.piInjections();
      expect(inj, isNotNull);
    });

    test('processes suspiciousOnly filter actually filters', () async {
      final api = await testApi();
      final all = await api.piProcesses();
      final suspicious = await api.piProcesses(suspiciousOnly: true);
      expect(suspicious.length, lessThanOrEqualTo(all.length));
    });

    test('memory/modules/handles/api-calls/behavioral/threat-intel/'
        'timeline/mitre/analytics load', () async {
      final api = await testApi();
      await api.piMemory();
      await api.piModules();
      await api.piHandles();
      await api.piApiCalls();
      await api.piBehavioral();
      await api.piThreatIntel();
      await api.piTimeline();
      await api.piMitreMap();
      await api.piAnalytics();
    });

    test('piRespond: empty hostname must give an honest error, not a '
        'confusing "no agent found with hostname \'—\'" (group-8 fix '
        'regression check)', () async {
      final api = await testApi();
      final res = await api.piRespond({
        'action': 'kill_process',
        'pid': 1234,
        'hostname': '',
      });
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue);
      expect((res['error'] as String).toLowerCase(), contains('hostname'),
          reason: 'empty hostname should surface a "hostname required" '
              'style error, not something derived from a placeholder value');
    });
  });
}
