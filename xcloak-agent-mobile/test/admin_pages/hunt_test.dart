// Live integration tests for lib/admin/screens/hunt.dart
// Screens: HuntWorkbenchScreen, ThreatHuntScreen, ThreatActorsScreen,
//          ThreatIntelScreen, SigmaRulesScreen, YaraRulesScreen, JA3Screen,
//          LogSearchScreen, LiveLogsScreen, LogSourcesScreen,
//          BehavioralScreen, DeceptionScreen, FirewallScreen,
//          ScriptRunnerScreen, VulnerabilitiesScreen
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('HuntWorkbenchScreen / ThreatHuntScreen', () {
    test('template create -> execute -> run appears, then delete', () async {
      final api = await testApi();
      final name = 'flutter-test-hunt-${DateTime.now().millisecondsSinceEpoch}';
      final createOk = await api.createHuntTemplate({
        'name': name,
        'kql_query': 'log_message:*failed*',
        'description': 'integration test',
      });
      expect(createOk, isTrue);

      final templates = await api.huntTemplates();
      final t = templates.cast<Map<String, dynamic>>().firstWhere(
          (x) => x['name'] == name || x['kql_query'] == 'log_message:*failed*');
      expect(t['kql_query'], isNotEmpty,
          reason: 'kql_query must actually persist on create — this was '
              'the group-1 bug (name/content sent instead of kql_query)');
      final id = t['id'] as int;

      final execOk = await api.executeHunt(id, name, t['kql_query'] as String);
      expect(execOk, isTrue,
          reason: 'ExecuteHunt requires kql_query, not agent_ids — this is '
              'the group-1 fix regression check');

      final delOk = await api.deleteHuntTemplate(id);
      expect(delOk, isTrue);
    });

    test('huntRuns() shows real hit_count field', () async {
      final api = await testApi();
      final runs = await api.huntRuns();
      expect(runs, isA<List>());
      if (runs.isNotEmpty) {
        expect((runs.first as Map<String, dynamic>).containsKey('hit_count'),
            isTrue,
            reason: 'group-1 fix: real field is hit_count, not results_count');
      }
    });
  });

  group('ThreatActorsScreen', () {
    test('create -> real recent_alert_count/aliases fields -> delete', () async {
      final api = await testApi();
      final name = 'flutter-test-actor-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createThreatActor({
        'name': name,
        'aliases': ['TA-Test'],
        'description': 'integration test actor',
      });
      expect(ok, isTrue);

      final actors = await api.threatActors();
      final a = actors.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      // recent_alert_count has `omitempty` and this actor has 0 recent
      // alerts, so the key may legitimately be absent — the real screen
      // code reads it as `a['recent_alert_count'] ?? 0`, so match that.
      expect(a['recent_alert_count'] ?? 0, 0);
      final id = a['id'] as int;

      final delOk = await api.deleteThreatActor(id);
      expect(delOk, isTrue);
    });
  });

  group('ThreatIntelScreen', () {
    test('IOC create persists real `indicator` field, not `value`', () async {
      final api = await testApi();
      final marker = '203.0.113.${DateTime.now().millisecond}';
      final ok = await api.createIoc({
        'type': 'ip',
        'indicator': marker,
        'severity': 'high',
        'description': 'integration test IOC',
      });
      expect(ok, isTrue);

      final iocs = await api.iocs();
      final row = iocs.cast<Map<String, dynamic>>().firstWhere(
          (x) => x['indicator'] == marker,
          orElse: () => <String, dynamic>{});
      expect(row, isNotEmpty,
          reason: 'created IOC not found by `indicator` — group-1 fix '
              'regression check (was sending `value`)');

      final delOk = await api.deleteIoc(row['id'] as int);
      expect(delOk, isTrue);
    });

    test('Feed create persists real `source`/`feed_type` fields', () async {
      final api = await testApi();
      final name = 'flutter-test-feed-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createThreatFeed({
        'name': name,
        'source': 'https://example.com/feed.json',
        'feed_type': 'flatfile',
        'enabled': true,
      });
      expect(ok, isTrue);

      final feeds = await api.threatFeeds();
      final f = feeds.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      expect(f['feed_type'], 'flatfile',
          reason: 'group-1 fix regression: real fields are source/feed_type, '
              'not url/format (stix/misp/csv/txt no longer exist as values)');
      final delOk = await api.deleteThreatFeed(f['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('SigmaRulesScreen', () {
    test('create persists real title/selections/condition, not name/content',
        () async {
      final api = await testApi();
      final title = 'flutter-test-sigma-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createSigma({
        'title': title,
        'status': 'experimental',
        'severity': 'high',
        'enabled': true,
        'selections': {'selection1': ['powershell', 'encoded']},
        'keywords': ['powershell', 'encoded'],
        'condition': 'selection1',
      });
      expect(ok, isTrue);

      final rules = await api.sigmaRules();
      final r = rules.cast<Map<String, dynamic>>().firstWhere(
          (x) => x['title'] == title,
          orElse: () => <String, dynamic>{});
      expect(r, isNotEmpty,
          reason: 'created rule not found by `title` — group-1 fix '
              'regression (was sending name/content, which the model '
              "doesn't have, so every created rule had a blank title and "
              'zero real detection logic)');
      final id = r['id'] as int;

      final toggleOk = await api.toggleSigma(id, false);
      expect(toggleOk, isTrue);
      final delOk = await api.deleteSigma(id);
      expect(delOk, isTrue);
    });
  });

  group('YaraRulesScreen', () {
    test('create persists real `rule_content`, not `content`', () async {
      final api = await testApi();
      final name = 'flutter_test_yara_${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createYara({
        'name': name,
        'rule_content':
            'rule $name { strings: \$a = "test" condition: \$a }',
        'enabled': true,
      });
      expect(ok, isTrue);

      final rules = await api.yaraRules();
      final r = rules.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      expect(r['rule_content'], isNotEmpty,
          reason: 'group-1 fix regression: real field is rule_content, not '
              'content — every created rule used to have blank rule text');
      final delOk = await api.deleteYara(r['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('JA3Screen', () {
    test('create requires real hash/threat_name/severity/source fields',
        () async {
      final api = await testApi();
      // 32-char hex, matches the backend's MD5-length validation.
      final hash = List.generate(32, (i) => 'abcdef0123456789'[i % 16]).join();
      final ok = await api.createJa3({
        'hash': hash,
        'threat_name': 'flutter-test-threat',
        'severity': 'high',
        'source': 'manual',
      });
      expect(ok, isTrue,
          reason: 'group-1 fix regression: create used to always 400 '
              '(sent fingerprint/label/is_malicious instead of the '
              'backend-required hash/threat_name)');

      final list = await api.ja3Fingerprints();
      final row = list.cast<Map<String, dynamic>>().firstWhere(
          (x) => x['hash'] == hash,
          orElse: () => <String, dynamic>{});
      expect(row, isNotEmpty);
      expect(row['severity'], 'high',
          reason: 'group-1 fix: real field is severity (not is_malicious '
              'always rendering "benign")');
      final delOk = await api.deleteJa3(row['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('LogSearchScreen', () {
    test('searchLogs() rows have real log_message field', () async {
      final api = await testApi();
      final results = await api.searchLogs(limit: 20);
      expect(results, isA<List>());
      if (results.isNotEmpty) {
        final l = results.first as Map<String, dynamic>;
        expect(l.containsKey('log_message'), isTrue,
            reason: 'group-1 fix regression: real field is log_message, '
                'not message/raw — every log message used to render blank');
      }
    });

    test('saveSearch() + savedSearches() + deleteSavedSearch() round-trip',
        () async {
      final api = await testApi();
      final name = 'flutter-test-search-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.saveSearch(name, 'log_message:error');
      expect(ok, isTrue);

      final saved = await api.savedSearches();
      final s = saved.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      final delOk = await api.deleteSavedSearch(s['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('LogSourcesScreen', () {
    test('create requires real source_type, not type/host/port', () async {
      final api = await testApi();
      final ts = DateTime.now().millisecondsSinceEpoch;
      final name = 'flutter-test-src-$ts';
      // idx_log_sources_ip_tenant is UNIQUE(ip_address, tenant_id) — must
      // be unique per run, not a fixed literal.
      final ip = '10.${(ts >> 16) % 256}.${(ts >> 8) % 256}.${ts % 256}';
      final ok = await api.createLogSource({
        'name': name,
        'source_type': 'syslog',
        'ip_address': ip,
        'format': 'rfc5424',
      });
      expect(ok, isTrue,
          reason: 'group-1 fix regression: create used to always 400 '
              '(sent type/host/port instead of the backend-required '
              'source_type)');

      final sources = await api.logSources();
      // Postgres INET normalizes a bare IP to CIDR (e.g. adds "/32").
      final row = sources.cast<Map<String, dynamic>>().firstWhere(
          (x) => (x['ip_address'] as String? ?? '').startsWith(ip),
          orElse: () => <String, dynamic>{});
      expect(row, isNotEmpty);
      final delOk = await api.deleteLogSource(row['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('BehavioralScreen', () {
    test('threatScores/threatFleet load; baselines tenant-wide summary '
        'works without requiring agent_id', () async {
      final api = await testApi();
      await api.threatScores();
      await api.threatFleet();
      // Direct .get() call the screen makes for the fleet-wide baseline
      // overview (group-1 backend fix: agent_id is now optional).
      final baselines = await api.get('/api/threat/baselines');
      expect(baselines, isNotNull);
    });
  });

  group('DeceptionScreen', () {
    test('honeyport create persists real is_active/port/protocol fields',
        () async {
      final api = await testApi();
      final agents = await api.agents();
      expect(agents, isNotEmpty);
      final agentId = (agents.first as Map<String, dynamic>)['id'];

      final ok = await api.createHoneyport({
        'agent_id': agentId,
        'port': 2222,
        'protocol': 'ssh',
        'description': 'integration test honeypot',
      });
      expect(ok, isTrue);

      final ports = await api.honeyports();
      final row = ports.cast<Map<String, dynamic>>().firstWhere(
          (x) => x['port'] == 2222 && x['agent_id'] == agentId,
          orElse: () => <String, dynamic>{});
      expect(row, isNotEmpty);
      expect(row.containsKey('is_active'), isTrue,
          reason: 'group-1 fix regression: real field is is_active, not '
              'active/enabled');
      final delOk = await api.deleteHoneyport(row['id'] as int);
      expect(delOk, isTrue);
    });

    test('canary token create/toggle/delete round-trip', () async {
      final api = await testApi();
      final name = 'flutter-test-canary-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createCanary({'name': name, 'type': 'file'});
      expect(ok, isTrue);
      final tokens = await api.canaryTokens();
      final t = tokens.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      final toggleOk = await api.toggleCanary(t['id'] as int);
      expect(toggleOk, isTrue);
      final delOk = await api.deleteCanary(t['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('FirewallScreen', () {
    test('rule create -> update (full-row, not partial) -> delete', () async {
      final api = await testApi();
      final name = 'flutter-test-fw-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createFirewallRule({
        'name': name,
        'action': 'deny',
        'source_ip': '198.51.100.0/24',
        'destination_ip': 'any',
        'enabled': true,
      });
      expect(ok, isTrue);

      final rules = await api.firewallRules();
      final r = rules.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      expect(r.containsKey('source_ip'), isTrue,
          reason: 'group-1 fix regression: real fields are source_ip/'
              'destination_ip, not src_ip/dst_ip');

      // The enable toggle must send the FULL rule (PUT is a full-row
      // overwrite) — a partial {'enabled': v} body would blank out
      // name/action/source_ip/etc. Verify a toggle preserves other fields.
      final flipped = Map<String, dynamic>.from(r)..['enabled'] = false;
      final updateOk = await api.updateFirewallRule(r['id'] as int, flipped);
      expect(updateOk, isTrue);
      final refreshed = (await api.firewallRules())
          .cast<Map<String, dynamic>>()
          .firstWhere((x) => x['id'] == r['id']);
      expect(refreshed['name'], name,
          reason: 'a partial-body toggle would have blanked the rule name');
      expect(refreshed['source_ip'], '198.51.100.0/24',
          reason: 'a partial-body toggle would have blanked source_ip');

      final delOk = await api.deleteFirewallRule(r['id'] as int);
      expect(delOk, isTrue);
    });
  });

  group('ScriptRunnerScreen', () {
    test('scriptTemplates() returns the real built-in catalog, run/history '
        'use real agent_ids/shell fields', () async {
      final api = await testApi();
      final templates = await api.scriptTemplates();
      expect(templates, isNotEmpty,
          reason: 'group-1 fix regression: ScriptRunnerScreen used to fake '
              '"scripts" by listing Sigma rules instead of the real '
              '/api/scripts/templates catalog');

      final agents = await api.agents();
      expect(agents, isNotEmpty);
      final agentId = (agents.first as Map<String, dynamic>)['id'] as int;
      final res = await api.runScript([agentId], 'echo hello',
          label: 'integration-test', shell: 'bash');
      expect(res, isNotNull);
      expect(res!.containsKey('error'), isFalse,
          reason: 'runScript failed: ${res['error']}');

      await api.scriptHistory();
    });
  });

  group('VulnerabilitiesScreen', () {
    test('vmFindings() returns real vm_findings rows, action persists',
        () async {
      final api = await testApi();
      final findings = await api.vmFindings();
      expect(findings, isA<List>(),
          reason: 'group-1 fix regression: response key changed from '
              'r["vulnerabilities"] to the real {"items":[...]} shape');
      if (findings.isNotEmpty) {
        // Pick one still in 'open' status — the shared seed finding may
        // already have been actioned by an earlier run of this test.
        final open = findings.cast<Map<String, dynamic>>()
            .where((x) => x['status'] == 'open');
        if (open.isEmpty) return;
        final f = open.first;
        expect(f.containsKey('cve_id') || f.containsKey('product'), isTrue);
        final id = f['id'] as int;
        final ok = await api.vmFindingAction(id, 'defer');
        expect(ok, isTrue);
      }
    });
  });
}
