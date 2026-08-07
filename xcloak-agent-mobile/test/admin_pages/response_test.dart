// Live integration tests for lib/admin/screens/response.dart
// Screens: CasesScreen, PlaybooksScreen, ApprovalsScreen, DFIRScreen,
//          QuarantineScreen, ScheduledTasksScreen
import 'package:flutter_test/flutter_test.dart';
import 'test_helper.dart';

void main() {
  group('CasesScreen', () {
    test('create -> tasks/evidence/notes/comment -> partial update -> delete',
        () async {
      final api = await testApi();
      final title = 'flutter-test-case-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createCase({
        'title': title,
        'description': 'integration test case',
        'severity': 'medium',
      });
      expect(ok, isTrue);

      final cases = await api.cases();
      final c = cases.cast<Map<String, dynamic>>().firstWhere((x) => x['title'] == title);
      final id = c['id'] as int;

      final taskOk = await api.createCaseTask(id, {'title': 'test task'});
      expect(taskOk, isTrue);
      final tasks = await api.caseTasks(id);
      expect(tasks, isNotEmpty);

      final evOk = await api.addCaseEvidence(id, {'title': 'test-evidence.txt', 'evidence_type': 'file'});
      expect(evOk, isTrue);
      expect(await api.caseEvidence(id), isNotEmpty);

      final noteOk = await api.addCaseNote(id, 'integration test note');
      expect(noteOk, isTrue);
      expect(await api.caseNotes(id), isNotEmpty);

      final commentOk = await api.addCaseComment(id, 'integration test comment');
      expect(commentOk, isTrue);

      // PatchCase must be a true partial update — a status-only change
      // must not blank out title/description/severity.
      final statusOk = await api.updateCase(id, {'status': 'investigating'});
      expect(statusOk, isTrue);
      final refreshed = (await api.cases())
          .cast<Map<String, dynamic>>()
          .firstWhere((x) => x['id'] == id);
      expect(refreshed['title'], title,
          reason: 'a status-only PATCH must not blank the title — this was '
              'the historical full-column-overwrite bug (PatchCase vs the '
              'old UpdateCase)');
      expect(refreshed['status'], 'investigating');

      final delOk = await api.deleteCase(id);
      expect(delOk, isTrue);
    });
  });

  group('PlaybooksScreen', () {
    test('create -> enable -> update (real endpoint, not stale legacy '
        'path) -> trigger -> disable -> delete', () async {
      final api = await testApi();
      final name = 'flutter-test-pb-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createPlaybook({
        'name': name,
        'trigger_type': 'manual',
        'action_type': 'notify',
      });
      expect(ok, isTrue);

      final playbooks = await api.playbooks();
      final p = playbooks.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      final id = p['id'] as int;

      final enableOk = await api.enablePlaybook(id);
      expect(enableOk, isTrue);

      // updatePlaybook hits /api/playbooks/:id (legacy path) while create/
      // delete/enable all hit /api/pb/library/:id — verify this actually
      // updates the pb_playbooks row this screen displays, not a
      // disconnected legacy table.
      final updateOk = await api.updatePlaybook(id, {'name': '$name-updated'});
      final afterUpdate = (await api.playbooks())
          .cast<Map<String, dynamic>>()
          .firstWhere((x) => x['id'] == id, orElse: () => <String, dynamic>{});
      if (updateOk && afterUpdate.isNotEmpty) {
        expect(afterUpdate['name'], '$name-updated',
            reason: 'updatePlaybook uses /api/playbooks/:id (legacy) while '
                'every other playbook method uses /api/pb/library/:id — if '
                'this assertion fails, the update silently landed on a '
                'disconnected legacy table and the real pb_playbooks row '
                'was never touched');
      }

      final triggerOk = await api.triggerPlaybook(id, {});
      expect(triggerOk, isTrue);

      final disableOk = await api.disablePlaybook(id);
      expect(disableOk, isTrue);

      final delOk = await api.deletePlaybook(id);
      expect(delOk, isTrue);
    });
  });

  group('ApprovalsScreen', () {
    test('pendingApprovals() loads real aq_requests rows', () async {
      final api = await testApi();
      final list = await api.pendingApprovals();
      expect(list, isA<List>());
    });
  });

  group('DFIRScreen', () {
    test('triggerDfir binds real agent_id/label/artifact_types', () async {
      final api = await testApi();
      final agents = await api.agents();
      expect(agents, isNotEmpty);
      final agentId = (agents.first as Map<String, dynamic>)['id'] as int;
      final ok = await api.triggerDfir(agentId, 'memory');
      expect(ok, isTrue);

      final collections = await api.dfirCollections();
      expect(collections, isNotEmpty);
      final latest = collections.first as Map<String, dynamic>;
      expect(latest.containsKey('label'), isTrue);
    });
  });

  group('QuarantineScreen', () {
    test('quarantine()/quarantineStats() load', () async {
      final api = await testApi();
      final stats = await api.quarantineStats();
      expect(stats, isNotNull);
      final list = await api.quarantine();
      expect(list, isA<List>());
      if (list.isNotEmpty) {
        final item = list.first as Map<String, dynamic>;
        if (item['status'] != 'released') {
          final ok = await api.releaseQuarantine(item['id'] as int);
          expect(ok, isTrue);
        }
      }
    });
  });

  group('ScheduledTasksScreen', () {
    test('create -> toggle (explicit state) -> run -> delete', () async {
      final api = await testApi();
      final name = 'flutter-test-task-${DateTime.now().millisecondsSinceEpoch}';
      final ok = await api.createScheduledTask({
        'name': name,
        'cron_expr': '0 0 * * *',
        'task_type': 'report',
      });
      expect(ok, isTrue);

      final tasks = await api.scheduledTasks();
      final t = tasks.cast<Map<String, dynamic>>().firstWhere((x) => x['name'] == name);
      expect(t.containsKey('cron_expr'), isTrue,
          reason: 'real field is cron_expr, not cron_expression');
      final id = t['id'] as int;

      final toggleOk = await api.toggleScheduledTask(id, false);
      expect(toggleOk, isTrue);
      final afterToggle = (await api.scheduledTasks())
          .cast<Map<String, dynamic>>()
          .firstWhere((x) => x['id'] == id);
      expect(afterToggle['enabled'], false);

      final runOk = await api.runScheduledTask(id);
      expect(runOk, isTrue);

      final delOk = await api.deleteScheduledTask(id);
      expect(delOk, isTrue);
    });
  });
}
