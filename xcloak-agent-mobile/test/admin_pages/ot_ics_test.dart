// Live integration tests for lib/admin/screens/ot_ics.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('OTICSScreen', () {
    test('dashboard/assets/topology/protocols real data', () async {
      final api = await testApi();
      final dash = await api.otDashboard();
      expect(dash, isNotNull);
      final assets = await api.otAssets();
      expect(assets, isNotEmpty, reason: 'expected seeded OT assets');
      await api.otTopology();
      await api.otProtocols();
    });

    test('traffic/alerts/devices/threats/dpi/risk/vulnerabilities/zones/'
        'baseline/threat-intel/timeline all load', () async {
      final api = await testApi();
      await api.otTraffic();
      await api.otAlerts();
      await api.otDevices();
      await api.otThreats();
      await api.otDPI();
      await api.otRisk();
      await api.otVulnerabilities();
      await api.otZones();
      await api.otBaseline();
      await api.otThreatIntel();
      await api.otTimeline();
    });

    test('compliance/attack-paths/analytics load', () async {
      final api = await testApi();
      await api.otCompliance();
      await api.otAttackPaths();
      await api.otAnalytics();
    });

    test('otRespond requires real params', () async {
      final api = await testApi();
      final res = await api.otRespond({'action': 'unknown_action_xyz'});
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue);
    });
  });
}
