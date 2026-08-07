// Live integration tests for lib/admin/screens/defense_evasion.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('DefenseEvasionScreen', () {
    test('dashboard/controls/tamper real data', () async {
      final api = await testApi();
      final dash = await api.deDashboard();
      expect(dash, isNotNull);
      await api.deControls();
      await api.deTamper();
    });

    test('evasion-events category filter uses real category values '
        '(group-8 fix regression check — log_evasion/process_evasion/'
        'script_evasion/credential_bypass/network_evasion)', () async {
      final api = await testApi();
      final all = await api.deEvasionEvents();
      expect(all, isA<List>());
      var foundNonEmpty = false;
      for (final cat in ['log_evasion', 'process_evasion', 'script_evasion',
          'credential_bypass', 'network_evasion']) {
        final filtered = await api.deEvasionEvents(category: cat);
        if (filtered.isNotEmpty) foundNonEmpty = true;
        for (final row in filtered) {
          expect((row as Map<String, dynamic>)['category'], cat);
        }
      }
      if (all.isNotEmpty) {
        expect(foundNonEmpty, isTrue,
            reason: 'events exist but every real category filter returned '
                'empty — the category taxonomy may have regressed to the '
                'old fabricated values');
      }
    });

    test('log-evasion/behavioral/correlation/mitre/threat-intel/timeline/'
        'analytics load', () async {
      final api = await testApi();
      await api.deLogEvasion();
      await api.deBehavioral();
      await api.deCorrelation();
      await api.deMITRE();
      await api.deThreatIntel();
      await api.deTimeline();
      await api.deAnalytics();
    });

    test('deRespond requires real params', () async {
      final api = await testApi();
      final res = await api.deRespond({'action': 'restart_security_services', 'hostname': ''});
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isTrue);
    });
  });
}
