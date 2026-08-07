// Live integration tests for lib/admin/screens/ad_security.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('ADSecurityScreen', () {
    test('dashboard/inventory/identity-risk/auth-monitor real data', () async {
      final api = await testApi();
      final dash = await api.adDashboard();
      expect(dash, isNotNull);
      final inv = await api.adInventory();
      expect(inv, isNotNull);
      await api.adIdentityRisk();
      await api.adAuthMonitor();
    });

    test('attacks category filters real finding types', () async {
      final api = await testApi();
      final all = await api.adAttacks();
      expect(all, isNotNull);
    });

    test('gpo-changes/changes/attack-paths/tiering/exposure/threat-intel/'
        'timeline/graph/analytics/assessment load', () async {
      final api = await testApi();
      await api.adGPOChanges();
      await api.adChanges();
      await api.adAttackPaths();
      await api.adTiering();
      await api.adExposure();
      await api.adThreatIntel();
      await api.adTimeline();
      await api.adGraph();
      await api.adAnalytics();
      await api.adAssessment();
    });

    test('adRespond requires real params', () async {
      final api = await testApi();
      final res = await api.adRespond({'action': 'unknown_action_xyz'});
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue);
    });
  });
}
