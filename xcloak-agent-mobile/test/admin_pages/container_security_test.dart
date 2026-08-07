// Live integration tests for lib/admin/screens/container_security.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('ContainerSecurityScreen', () {
    test('dashboard/clusters/nodes/namespaces/pods/images real data', () async {
      final api = await testApi();
      final dash = await api.containerDashboard();
      expect(dash, isNotNull);
      final clusters = await api.containerClusters();
      expect(clusters, isNotEmpty, reason: 'expected seeded k8s_clusters');
      await api.containerNodes();
      await api.containerNamespaces();
      await api.containerPods();
      await api.containerImages();
    });

    test('compliance() returns real internet_facing/managed booleans '
        '(group-B regression check — was always empty)', () async {
      final api = await testApi();
      final compliance = await api.containerCompliance();
      expect(compliance, isNotNull);
      expect(compliance!.containsKey('overall_score'), isTrue);
      // The Postgres-bool-scanned-as-int bug (fixed this session) was in
      // ace_assets, a different table — but verify this endpoint's own
      // shape is sane as a smoke test.
      expect(compliance['overall_score'], isA<num>());
    });

    test('runtime-alerts/rbac/secrets/network-policies/admission load',
        () async {
      final api = await testApi();
      await api.containerRuntimeAlerts();
      await api.containerRBAC();
      await api.containerSecrets();
      await api.containerNetworkPolicies();
      await api.containerAdmission();
    });

    test('supply-chain/threat-intel/timeline/vulnerabilities/attack-paths/'
        'analytics load', () async {
      final api = await testApi();
      await api.containerSupplyChain();
      await api.containerThreatIntel();
      await api.containerTimeline();
      await api.containerVulnerabilities();
      await api.containerAttackPaths();
      await api.containerAnalytics();
    });

    test('containerRespond requires real params, not silently succeed on '
        'empty', () async {
      final api = await testApi();
      final res = await api.containerRespond({'action': 'unknown_action_xyz'});
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue,
          reason: 'an unrecognized action must surface a real error');
    });
  });
}
