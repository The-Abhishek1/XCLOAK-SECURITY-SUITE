// Live integration tests for lib/admin/screens/email_security.dart
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('EmailSecurityScreen', () {
    test('dashboard/mail-flow/messages load real data', () async {
      final api = await testApi();
      final dash = await api.emailDashboard();
      expect(dash, isNotNull);
      await api.emailMailFlow();
      final messages = await api.emailMessages();
      expect(messages, isA<List>());
    });

    test('search uses real OR-combined `q` param (group-6 fix regression)',
        () async {
      final api = await testApi();
      final all = await api.emailMessages();
      if (all.isEmpty) return;
      final msg = all.first as Map<String, dynamic>;
      final subjectWord = (msg['subject'] as String? ?? '').split(' ').first;
      if (subjectWord.isEmpty) return;
      final results = await api.emailMessages(search: subjectWord);
      expect(results, isNotEmpty,
          reason: 'searching a real subject word returned nothing — the '
              'AND-vs-OR search bug may have regressed');
    });

    test('threats/attachments/urls/auth-results load', () async {
      final api = await testApi();
      await api.emailThreats();
      await api.emailAttachments();
      await api.emailUrls();
      await api.emailAuthResults();
    });

    test('sender-intel/threat-intel/campaigns/timeline/user-risk/analytics '
        'load', () async {
      final api = await testApi();
      await api.emailSenderIntel(domain: 'example.com');
      await api.emailThreatIntel();
      await api.emailCampaigns();
      await api.emailTimeline();
      await api.emailUserRisk();
      await api.emailAnalytics();
    });

    test('policy create -> update -> delete round-trip', () async {
      final api = await testApi();
      final name = 'flutter-test-policy-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createEmailPolicy({
        'name': name,
        'policy_type': 'block_sender',
        'enabled': true,
      });
      expect(ok, isTrue);
      final policies = await api.emailPolicies();
      final p = policies.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      final id = p['id'] as int;
      final updateOk = await api.updateEmailPolicy(id, {'enabled': false});
      expect(updateOk, isTrue);
      final delOk = await api.deleteEmailPolicy(id);
      expect(delOk, isTrue);
    });

    test('patchEmailReported partial-update does not clobber analyst_notes '
        '(group-6 fix regression)', () async {
      final api = await testApi();
      final reported = await api.emailReported();
      if (reported.isEmpty) return;
      final r = reported.first as Map<String, dynamic>;
      final id = r['id'] as int;

      final notesOk = await api.patchEmailReported(id, analystNotes: 'flutter-test-notes');
      expect(notesOk, isTrue);

      // Mark reviewed WITHOUT re-sending notes — must not blank them.
      final reviewOk = await api.patchEmailReported(id, triageStatus: 'reviewed');
      expect(reviewOk, isTrue);

      final after = (await api.emailReported())
          .cast<Map<String, dynamic>>()
          .firstWhere((x) => x['id'] == id);
      expect(after['analyst_notes'], 'flutter-test-notes',
          reason: '"Mark Reviewed" must not wipe previously-saved '
              'analyst_notes — this was the group-6 clobber bug');
    });
  });
}
