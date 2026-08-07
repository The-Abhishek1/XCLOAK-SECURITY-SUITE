// Live integration tests for lib/admin/screens/supply_chain.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('SupplyChainScreen', () {
    test('dashboard/repositories/dependencies/vulnerabilities real data',
        () async {
      final api = await testApi();
      final dash = await api.supplyChainDashboard();
      expect(dash, isNotNull);
      final repos = await api.supplyChainRepositories();
      expect(repos, isNotEmpty, reason: 'expected seeded sc_repositories');
      await api.supplyChainDependencies();
      await api.supplyChainVulnerabilities();
    });

    test('sboms/pipelines/secrets/code-integrity/artifacts/third-party/'
        'provenance/threat-intel/timeline/analytics/compliance load',
        () async {
      final api = await testApi();
      await api.supplyChainSBOMs();
      await api.supplyChainPipelines();
      await api.supplyChainSecrets();
      await api.supplyChainCodeIntegrity();
      await api.supplyChainArtifacts();
      await api.supplyChainThirdParty();
      await api.supplyChainProvenance();
      await api.supplyChainThreatIntel();
      await api.supplyChainTimeline();
      // group-7 fix regression check: AVG() scanned into int used to
      // silently drop every row of "Most Vulnerable Projects".
      final analytics = await api.supplyChainAnalytics();
      expect(analytics, isNotNull);
      await api.supplyChainCompliance();
    });

    test('policy create -> update -> delete round-trip', () async {
      final api = await testApi();
      final name = 'flutter-test-policy-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createSupplyChainPolicy({
        'name': name,
        'rule_type': 'block_unsigned',
        'action': 'block',
        'is_enabled': true,
      });
      expect(ok, isTrue);
      final policies = await api.supplyChainPolicies();
      final p = policies.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      final id = p['id'] as int;
      final updateOk = await api.patchSupplyChainPolicy(id, {'is_enabled': false});
      expect(updateOk, isTrue);
      final delOk = await api.deleteSupplyChainPolicy(id);
      expect(delOk, isTrue);
    });

    test('supplyChainRespond requires real params', () async {
      final api = await testApi();
      final res = await api.supplyChainRespond({'action': 'unknown_action_xyz'});
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue);
    });
  });
}
