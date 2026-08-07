// Live integration tests for lib/admin/screens/cloud_security.dart
// Screen: CloudSecurityScreen (Overview/Inventory/CSPM/CIEM/Detection/
// Compliance/Attack Paths/Analytics tabs)
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('CloudSecurityScreen', () {
    test('dashboard/accounts/inventory all return real seeded data', () async {
      final api = await testApi();
      final dash = await api.cloudDashboard();
      expect(dash, isNotNull);

      final accounts = await api.cloudAccounts();
      expect(accounts, isNotEmpty, reason: 'expected seeded cloud accounts');

      final inventory = await api.cloudInventory();
      expect(inventory, isNotEmpty, reason: 'expected seeded cloud assets');
    });

    test('createCloudAccount() + deleteCloudAccount() round-trip', () async {
      final api = await testApi();
      final ok = await api.createCloudAccount({
        'provider': 'aws',
        'account_name': 'flutter-test-${DateTime.now().millisecondsSinceEpoch}',
        'region': 'us-east-1',
      });
      expect(ok, isTrue);
      final accounts = await api.cloudAccounts();
      final a = accounts.cast<Map<String, dynamic>>().last;
      final delOk = await api.deleteCloudAccount(a['id'] as int);
      expect(delOk, isTrue);
    });

    test('CSPM findings load, patchCloudFinding() persists a status change',
        () async {
      final api = await testApi();
      final findings = await api.cloudCSPMFindings();
      expect(findings, isA<List>());
      if (findings.isNotEmpty) {
        final f = findings.first as Map<String, dynamic>;
        final ok = await api.patchCloudFinding(f['id'] as int, 'acknowledged');
        expect(ok, isTrue);
      }
      await api.cloudCSPMSummary();
    });

    test('CIEM identities/risks load', () async {
      final api = await testApi();
      await api.cloudIdentities();
      await api.cloudCIEMRisks();
    });

    test('Detection: threats load, cloudRespond block_ip requires a real '
        'source_ip (empty must not silently "succeed")', () async {
      final api = await testApi();
      final threats = await api.cloudThreats();
      expect(threats, isA<List>());
      final res = await api.cloudRespond({
        'action': 'block_ip',
        'resource_id': '',
        'provider': '',
        'source_user': '',
        'source_ip': '',
      });
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue,
          reason: 'group-8 fix regression: an empty source_ip must trigger '
              'the backend\'s real validation error, not silently "succeed" '
              'and write a garbage IOC');
    });

    test('compliance/timeline/attack-paths/drift/vulnerabilities/'
        'threat-intel/analytics all load', () async {
      final api = await testApi();
      await api.cloudCompliance();
      await api.cloudTimeline();
      await api.cloudAttackPaths();
      final drift = await api.cloudDrift();
      expect(drift, isA<List>());
      if (drift.isNotEmpty) {
        final ok = await api.ackCloudDrift((drift.first as Map<String, dynamic>)['id'] as int);
        expect(ok, isTrue);
      }
      await api.cloudVulnerabilities();
      await api.cloudThreatIntel();
      await api.cloudAnalytics();
    });
  });
}
