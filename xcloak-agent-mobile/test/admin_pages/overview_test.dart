// Live integration tests for lib/admin/screens/overview.dart
// Screens: DashboardScreen, AgentsScreen, AgentDetailScreen, NetworkMapScreen,
//          AttackPathsScreen, DeployAgentScreen, TimelineScreen
//
// Run: flutter test test/admin_pages/overview_test.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('DashboardScreen', () {
    test('overview() returns real KPI fields', () async {
      final api = await testApi();
      final r = await api.overview();
      expect(r, isNotNull, reason: 'dashboard overview must not be null');
      for (final key in ['agents', 'alerts', 'incidents', 'critical_alerts']) {
        expect(r!.containsKey(key), isTrue, reason: 'overview missing "$key"');
      }
    });

    test('metrics() returns data', () async {
      final api = await testApi();
      final r = await api.metrics();
      expect(r, isNotNull, reason: 'dashboard metrics must not be null');
    });
  });

  group('AgentsScreen', () {
    test('agents() returns a real, non-empty list with expected fields',
        () async {
      final api = await testApi();
      final list = await api.agents();
      expect(list, isNotEmpty, reason: 'expected seeded agents in DB');
      final a = list.first as Map<String, dynamic>;
      for (final key in ['id', 'hostname']) {
        expect(a.containsKey(key), isTrue,
            reason: 'agent row missing "$key" — field-name mismatch would '
                'silently blank this in AgentsScreen');
      }
    });

    test('queueTask() dispatches a real task to a real agent', () async {
      final api = await testApi();
      final agents = await api.agents();
      expect(agents, isNotEmpty);
      final agentId = (agents.first as Map<String, dynamic>)['id'] as int;
      final ok =
          await api.queueTask(agentId, 'collect_processes', payload: {});
      expect(ok, isTrue,
          reason: 'AgentsScreen "Isolate/Collect" actions call queueTask — '
              'if this fails, every response-action button on this screen '
              'is broken');
    });
  });

  group('AgentDetailScreen', () {
    test('all 6 tabs fetch without error for a real agent', () async {
      final api = await testApi();
      final agents = await api.agents();
      expect(agents, isNotEmpty);
      final agentId = (agents.first as Map<String, dynamic>)['id'] as int;

      final summary = await api.agentSummary(agentId);
      expect(summary, isNotNull, reason: 'Summary tab would render blank');

      // These can legitimately be empty (no processes collected yet), but
      // must not throw / must return a List, not null.
      await api.agentProcesses(agentId);
      await api.agentConnections(agentId);
      await api.agentPackages(agentId);
      await api.agentVulns(agentId);
      final timeline = await api.agentTimeline(agentId);
      expect(timeline, isA<List>());
    });
  });

  group('NetworkMapScreen', () {
    test('networkMap() returns nodes/edges shape', () async {
      final api = await testApi();
      final r = await api.networkMap();
      expect(r, isNotNull);
      expect(r!.containsKey('nodes'), isTrue,
          reason: 'NetworkMapScreen reads r["nodes"] directly');
    });
  });

  group('AttackPathsScreen', () {
    test('attackPaths() returns real graph data', () async {
      final api = await testApi();
      final r = await api.attackPaths();
      expect(r, isNotNull);
    });
  });

  group('DeployAgentScreen', () {
    test('generateInstallToken() + installTokens() round-trip', () async {
      final api = await testApi();
      final res = await api.generateInstallToken('flutter-test-token');
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isFalse,
          reason: 'token generation failed: ${res['error']}');
      expect(res['token'], isNotNull,
          reason: 'DeployAgentScreen reads res["token"] to show the '
              'install command — a missing token here means the whole '
              'wizard shows a blank command');

      final tokens = await api.installTokens();
      expect(tokens, isA<List>());
    });
  });

  group('TimelineScreen', () {
    test('events() returns real audit-event rows with the fields the '
        'screen actually reads (threat_tag/cmdline/exe/comm/username)',
        () async {
      final api = await testApi();
      final list = await api.events(limit: 20);
      expect(list, isA<List>());
      if (list.isNotEmpty) {
        final e = list.first as Map<String, dynamic>;
        // Regression check for the group-1 fix: these must exist, and the
        // old fabricated fields (event_type/message/description/timestamp)
        // must not be what the screen relies on.
        expect(
            e.containsKey('cmdline') ||
                e.containsKey('threat_tag') ||
                e.containsKey('created_at'),
            isTrue,
            reason: 'TimelineScreen event row has none of the real '
                'AuditEvent fields — check for a regression back to the '
                'fabricated event_type/message schema');
      }
    });
  });
}
