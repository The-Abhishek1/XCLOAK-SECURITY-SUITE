import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Cases Screen — rich cards with status tabs
// ─────────────────────────────────────────────────────────────────────────────

class CasesScreen extends StatefulWidget {
  final DashboardApi api;
  const CasesScreen({super.key, required this.api});
  @override State<CasesScreen> createState() => _CasesState();
}

class _CasesState extends State<CasesScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  final _statuses = ['open', 'in_progress', 'closed'];
  List _cases   = [];
  bool _loading = true;
  String _status = 'open';

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 3, vsync: this);
    _tabs.addListener(() {
      if (!_tabs.indexIsChanging) {
        setState(() => _status = _statuses[_tabs.index]);
        _load();
      }
    });
    _load();
  }

  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.cases(status: _status);
    if (!mounted) return;
    setState(() { _cases = r; _loading = false; });
  }

  void _showCreate() {
    final titleCtrl = TextEditingController();
    final descCtrl  = TextEditingController();
    String sev      = 'medium';
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (_) => StatefulBuilder(builder: (ctx, ss) =>
        Padding(
          padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
              sheetHeader('New Case'),
              const SizedBox(height: 16),
              xField(titleCtrl, 'Case Title'),
              const SizedBox(height: 10),
              xField(descCtrl,  'Description', maxLines: 3),
              const SizedBox(height: 10),
              xDropdown('Severity', sev, const ['critical', 'high', 'medium', 'low'], (v) => ss(() => sev = v!)),
              const SizedBox(height: 16),
              SizedBox(width: double.infinity, child: FilledButton.icon(
                icon: const Icon(Icons.folder_open, size: 16),
                label: const Text('Create Case'),
                onPressed: () async {
                  Navigator.pop(context);
                  final ok = await widget.api.createCase({
                    'title': titleCtrl.text, 'description': descCtrl.text, 'severity': sev,
                  });
                  if (context.mounted) xSnack(context, ok ? 'Case created' : 'Failed', error: !ok);
                  _load();
                },
              )),
            ]),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.add),
        label: const Text('New Case'),
      ),
      body: Column(children: [
        TabBar(
          controller: _tabs,
          labelStyle: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700),
          tabs: const [Tab(text: 'Open'), Tab(text: 'In Progress'), Tab(text: 'Closed')],
        ),
        Expanded(child: _loading
          ? xLoading()
          : _cases.isEmpty
            ? XEmptyState(
                _status == 'closed' ? 'No closed cases' : 'No ${_status.replaceAll('_', ' ')} cases',
                icon: Icons.folder_outlined)
            : RefreshIndicator(
                onRefresh: _load,
                child: ListView.builder(
                  padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
                  itemCount: _cases.length,
                  itemBuilder: (_, i) => _CaseCard(
                    c: _cases[i] as Map<String,dynamic>,
                    api: widget.api,
                    onAction: _load,
                  ),
                ),
              )),
      ]),
    );
  }
}

class _CaseCard extends StatelessWidget {
  final Map<String,dynamic> c;
  final DashboardApi api;
  final VoidCallback onAction;
  const _CaseCard({required this.c, required this.api, required this.onAction});

  Color _priorityColor() {
    final p = str(c['priority'] ?? c['severity']);
    return switch (p) {
      'critical' => const Color(0xFFEF4444),
      'high'     => const Color(0xFFF97316),
      'medium'   => const Color(0xFFF59E0B),
      _          => const Color(0xFF22C55E),
    };
  }

  int get _age {
    try {
      final dt = DateTime.parse(c['created_at'].toString());
      return DateTime.now().difference(dt).inDays;
    } catch (_) { return 0; }
  }

  void _showDetail(BuildContext context) {
    final id = c['id'] as int? ?? 0;
    showModalBottomSheet(
      context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (_) => _CaseDetailSheet(caseId: id, title: str(c['title']), api: api),
    );
  }

  @override
  Widget build(BuildContext context) {
    final id  = c['id'] as int? ?? 0;
    final col = _priorityColor();

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      clipBehavior: Clip.hardEdge,
      child: InkWell(
        onTap: () => _showDetail(context),
        child: Row(children: [
        Container(width: 4, color: col),
        Expanded(child: Padding(
          padding: const EdgeInsets.fromLTRB(12, 12, 8, 12),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            // Title + ID + status
            Row(children: [
              Expanded(child: Text(str(c['title']),
                style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w800))),
              Text('#$id', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ]),
            const SizedBox(height: 6),
            // Tags row
            Row(children: [
              SevChip(str(c['severity'] ?? c['priority'])),
              const SizedBox(width: 6),
              StatusChip(str(c['status'])),
              const SizedBox(width: 6),
              if (_age > 0) Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: (_age > 7 ? const Color(0xFFEF4444) : Colors.grey).withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(6)),
                child: Text('${_age}d old', style: TextStyle(
                  fontSize: 10, fontWeight: FontWeight.w700,
                  color: _age > 7 ? const Color(0xFFEF4444) : Colors.grey)),
              ),
            ]),
            if (c['description'] != null && c['description'].toString().isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(str(c['description']),
                style: const TextStyle(fontSize: 12.5, color: Colors.grey),
                maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 8),
            // Footer row
            Row(children: [
              const Icon(Icons.access_time, size: 12, color: Colors.grey),
              const SizedBox(width: 4),
              Text(timeAgo(c['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
              if ((c['owner'] ?? '').toString().isNotEmpty) ...[
                const SizedBox(width: 12),
                const Icon(Icons.person_outline, size: 12, color: Colors.grey),
                const SizedBox(width: 4),
                Text(str(c['owner']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ],
              const Spacer(),
              PopupMenuButton<String>(
                onSelected: (action) async {
                  if (action == 'comment') {
                    final ctrl = TextEditingController();
                    if (!context.mounted) return;
                    await showDialog(context: context, builder: (_) => AlertDialog(
                      title: const Text('Add Comment'),
                      content: TextField(controller: ctrl, maxLines: 3,
                        decoration: const InputDecoration(hintText: 'Comment text…')),
                      actions: [
                        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
                        FilledButton(onPressed: () async {
                          Navigator.pop(context);
                          final ok = await api.addCaseComment(id, ctrl.text);
                          if (context.mounted) xSnack(context, ok ? 'Comment added' : 'Failed', error: !ok);
                        }, child: const Text('Add')),
                      ],
                    ));
                  } else if (action == 'close') {
                    final ok = await api.updateCase(id, {'status': 'closed'});
                    if (context.mounted) xSnack(context, ok ? 'Case closed' : 'Failed', error: !ok);
                    onAction();
                  } else if (action == 'in_progress') {
                    final ok = await api.updateCase(id, {'status': 'in_progress'});
                    if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                    onAction();
                  } else if (action == 'delete') {
                    if (!context.mounted) return;
                    if (await xConfirm(context, 'Delete Case', 'Delete case #$id permanently?')) {
                      final ok = await api.deleteCase(id);
                      if (context.mounted) xSnack(context, ok ? 'Deleted' : 'Failed', error: !ok);
                      onAction();
                    }
                  }
                },
                itemBuilder: (_) => [
                  const PopupMenuItem(value: 'comment',     child: Text('Add Comment')),
                  const PopupMenuItem(value: 'in_progress', child: Text('→ In Progress')),
                  const PopupMenuItem(value: 'close',       child: Text('→ Close')),
                  const PopupMenuDivider(),
                  const PopupMenuItem(value: 'delete',
                    child: Text('Delete', style: TextStyle(color: Colors.redAccent))),
                ],
              ),
            ]),
          ]),
        )),
      ]),
      ),
    );
  }
}

// ── Case Detail Sheet — Tasks / Evidence / Notes ─────────────────────────────

class _CaseDetailSheet extends StatefulWidget {
  final int caseId;
  final String title;
  final DashboardApi api;
  const _CaseDetailSheet({required this.caseId, required this.title, required this.api});
  @override State<_CaseDetailSheet> createState() => _CaseDetailSheetState();
}

class _CaseDetailSheetState extends State<_CaseDetailSheet> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _tasks = [], _evidence = [], _notes = [];
  bool _loading = true;

  @override void initState() {
    super.initState();
    _tabs = TabController(length: 3, vsync: this);
    _load();
  }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([
      widget.api.caseTasks(widget.caseId),
      widget.api.caseEvidence(widget.caseId),
      widget.api.caseNotes(widget.caseId),
    ]);
    if (!mounted) return;
    setState(() { _tasks = res[0]; _evidence = res[1]; _notes = res[2]; _loading = false; });
  }

  void _addTask() {
    final titleCtrl = TextEditingController();
    String priority = 'medium';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Task'),
          xField(titleCtrl, 'Task title'),
          const SizedBox(height: 10),
          xDropdown('Priority', priority, ['critical','high','medium','low'], (v) => ss(() => priority = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createCaseTask(widget.caseId, {'title': titleCtrl.text.trim(), 'priority': priority});
              if (context.mounted) xSnack(context, ok ? 'Task added' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Add'),
          )),
        ]),
      )),
    );
  }

  void _addEvidence() {
    final titleCtrl = TextEditingController();
    final hashCtrl  = TextEditingController();
    String type = 'file';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Evidence'),
          xField(titleCtrl, 'Title'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['file','log','screenshot','memory_dump','disk_image','network_capture'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xField(hashCtrl, 'File hash (optional)'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.addCaseEvidence(widget.caseId, {'title': titleCtrl.text.trim(), 'evidence_type': type, 'file_hash': hashCtrl.text.trim()});
              if (context.mounted) xSnack(context, ok ? 'Evidence logged' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Add'),
          )),
        ]),
      )),
    );
  }

  void _addNote() {
    final ctrl = TextEditingController();
    showDialog(context: context, builder: (_) => AlertDialog(
      title: const Text('Add Note'),
      content: TextField(controller: ctrl, maxLines: 4, decoration: const InputDecoration(hintText: 'Note (markdown supported)…')),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton(onPressed: () async {
          Navigator.pop(context);
          final ok = await widget.api.addCaseNote(widget.caseId, ctrl.text.trim());
          if (context.mounted) xSnack(context, ok ? 'Note added' : 'Failed', error: !ok);
          _load();
        }, child: const Text('Add')),
      ],
    ));
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return DraggableScrollableSheet(
      initialChildSize: 0.75, maxChildSize: 0.95, minChildSize: 0.4, expand: false,
      builder: (_, ctrl) => Container(
        decoration: BoxDecoration(color: cs.surface, borderRadius: const BorderRadius.vertical(top: Radius.circular(20))),
        child: Column(children: [
          Center(child: Container(
            width: 38, height: 4, margin: const EdgeInsets.symmetric(vertical: 10),
            decoration: BoxDecoration(color: cs.outlineVariant, borderRadius: BorderRadius.circular(2)))),
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Text(widget.title, style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w800))),
          const SizedBox(height: 8),
          TabBar(controller: _tabs, tabs: const [Tab(text: 'Tasks'), Tab(text: 'Evidence'), Tab(text: 'Notes')]),
          const Divider(height: 1),
          Expanded(child: _loading ? const Center(child: CircularProgressIndicator()) : TabBarView(
            controller: _tabs,
            children: [
              _tasksTab(ctrl),
              _evidenceTab(ctrl),
              _notesTab(ctrl),
            ],
          )),
        ]),
      ),
    );
  }

  Widget _tasksTab(ScrollController ctrl) => Scaffold(
    floatingActionButton: FloatingActionButton.small(onPressed: _addTask, child: const Icon(Icons.add)),
    body: _tasks.isEmpty
      ? const Center(child: Text('No tasks', style: TextStyle(color: Colors.grey)))
      : ListView.builder(
          controller: ctrl,
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 80),
          itemCount: _tasks.length,
          itemBuilder: (_, i) {
            final t = _tasks[i] as Map<String,dynamic>;
            final taskId = t['id'] as int? ?? 0;
            final done = str(t['status']) == 'done' || str(t['status']) == 'completed';
            return CheckboxListTile(
              value: done,
              onChanged: (v) async {
                await widget.api.updateCaseTask(widget.caseId, taskId, {'status': v! ? 'done' : 'pending'});
                _load();
              },
              title: Text(str(t['title']), style: TextStyle(fontSize: 13, decoration: done ? TextDecoration.lineThrough : null)),
              subtitle: Text('${str(t['priority'])}  ·  ${str(t['assignee'], 'unassigned')}', style: const TextStyle(fontSize: 11)),
            );
          },
        ),
  );

  Widget _evidenceTab(ScrollController ctrl) => Scaffold(
    floatingActionButton: FloatingActionButton.small(onPressed: _addEvidence, child: const Icon(Icons.add)),
    body: _evidence.isEmpty
      ? const Center(child: Text('No evidence logged', style: TextStyle(color: Colors.grey)))
      : ListView.builder(
          controller: ctrl,
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 80),
          itemCount: _evidence.length,
          itemBuilder: (_, i) {
            final e = _evidence[i] as Map<String,dynamic>;
            return ListTile(
              leading: Icon(e['verified'] == true ? Icons.verified : Icons.pending_outlined, size: 18),
              title: Text(str(e['title']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              subtitle: Text('${str(e['evidence_id'])}  ·  ${str(e['evidence_type'])}  ·  ${str(e['collector'], 'unknown')}',
                style: const TextStyle(fontSize: 11)),
            );
          },
        ),
  );

  Widget _notesTab(ScrollController ctrl) => Scaffold(
    floatingActionButton: FloatingActionButton.small(onPressed: _addNote, child: const Icon(Icons.add)),
    body: _notes.isEmpty
      ? const Center(child: Text('No notes', style: TextStyle(color: Colors.grey)))
      : ListView.builder(
          controller: ctrl,
          padding: const EdgeInsets.fromLTRB(16, 8, 16, 80),
          itemCount: _notes.length,
          itemBuilder: (_, i) {
            final n = _notes[i] as Map<String,dynamic>;
            return Padding(
              padding: const EdgeInsets.only(bottom: 12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(str(n['content']), style: const TextStyle(fontSize: 13)),
                const SizedBox(height: 4),
                Text('${str(n['author'], 'analyst')}  ·  ${timeAgo(n['created_at'])}',
                  style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
              ]),
            );
          },
        ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Playbooks Screen — rich cards with step count, run button, toggle
// ─────────────────────────────────────────────────────────────────────────────

class PlaybooksScreen extends StatefulWidget {
  final DashboardApi api;
  const PlaybooksScreen({super.key, required this.api});
  @override State<PlaybooksScreen> createState() => _PlaybooksState();
}

class _PlaybooksState extends State<PlaybooksScreen> {
  List _books       = [];
  List _executions  = [];
  bool _loading     = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.playbooks().then((r)          => _books      = r),
      widget.api.playbookExecutions().then((r) => _executions = r),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  void _showCreate() {
    final nameCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    String trigger  = 'manual';
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('New Playbook'),
            const SizedBox(height: 16),
            xField(nameCtrl, 'Playbook Name'),
            const SizedBox(height: 10),
            xField(descCtrl, 'Description', maxLines: 2),
            const SizedBox(height: 10),
            xDropdown('Trigger', trigger, const ['manual', 'alert', 'incident', 'scheduled'], (v) => ss(() => trigger = v!)),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.auto_awesome, size: 16),
              label: const Text('Create Playbook'),
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createPlaybook({
                  'name': nameCtrl.text, 'description': descCtrl.text,
                  'trigger_type': trigger,
                });
                if (context.mounted) xSnack(context, ok ? 'Playbook created' : 'Failed', error: !ok);
                _load();
              },
            )),
          ]),
        ),
      )),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.add),
        label: const Text('New Playbook'),
      ),
      body: RefreshIndicator(
        onRefresh: _load,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
          children: [
            // Recent executions strip
            if (_executions.isNotEmpty) ...[
              SectionTitle('Recent Runs'),
              SizedBox(
                height: 72,
                child: ListView.builder(
                  scrollDirection: Axis.horizontal,
                  itemCount: _executions.take(10).length,
                  itemBuilder: (_, i) {
                    final ex  = _executions[i] as Map<String,dynamic>;
                    final ok  = str(ex['status']) == 'completed';
                    final col = ok ? const Color(0xFF22C55E) : const Color(0xFFEF4444);
                    return Container(
                      width: 130,
                      margin: const EdgeInsets.only(right: 8),
                      padding: const EdgeInsets.all(10),
                      decoration: BoxDecoration(
                        color: col.withValues(alpha: .06),
                        borderRadius: BorderRadius.circular(10),
                        border: Border.all(color: col.withValues(alpha: .25))),
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Row(children: [
                          Icon(ok ? Icons.check_circle : Icons.cancel, size: 12, color: col),
                          const SizedBox(width: 4),
                          Expanded(child: Text(str(ex['playbook_name'] ?? 'Playbook'),
                            style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w700),
                            maxLines: 1, overflow: TextOverflow.ellipsis)),
                        ]),
                        const Spacer(),
                        Text(timeAgo(ex['started_at'] ?? ex['created_at']),
                          style: const TextStyle(fontSize: 10, color: Colors.grey)),
                      ]),
                    );
                  },
                ),
              ),
              const SizedBox(height: 14),
            ],

            SectionTitle('Playbooks'),
            if (_books.isEmpty)
              const XEmptyState('No playbooks', icon: Icons.auto_awesome_outlined)
            else
              ..._books.map((b) => _PlaybookCard(
                book: b as Map<String,dynamic>,
                api: widget.api,
                onAction: _load,
              )),
          ],
        ),
      ),
    );
  }
}

class _PlaybookCard extends StatelessWidget {
  final Map<String,dynamic> book;
  final DashboardApi api;
  final VoidCallback onAction;
  const _PlaybookCard({required this.book, required this.api, required this.onAction});

  @override
  Widget build(BuildContext context) {
    // pb_playbooks — status (draft/active/archived), not a bare `enabled`
    // bool; step count lives in the workflow JSON, not the list response,
    // so execution_count is shown instead.
    final id      = book['id'] as int? ?? 0;
    final enabled = str(book['status']) == 'active';
    final execCount = book['execution_count'] ?? 0;
    final trigger = str(book['trigger_type'], 'manual');
    final col     = enabled ? const Color(0xFF22C55E) : Colors.grey;

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Container(
              width: 38, height: 38,
              decoration: BoxDecoration(
                color: col.withValues(alpha: .1),
                borderRadius: BorderRadius.circular(10)),
              child: Icon(Icons.auto_awesome, size: 20, color: col)),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(book['name']),
                style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w800)),
              const SizedBox(height: 2),
              Row(children: [
                _Tag(Icons.play_circle_outline, _triggerLabel(trigger)),
                const SizedBox(width: 8),
                _Tag(Icons.history, '$execCount runs'),
              ]),
            ])),
            Switch(
              value: enabled,
              onChanged: (_) async {
                final ok = enabled
                  ? await api.disablePlaybook(id)
                  : await api.enablePlaybook(id);
                if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                onAction();
              },
            ),
          ]),
          if (book['description'] != null && book['description'].toString().isNotEmpty) ...[
            const SizedBox(height: 8),
            Text(str(book['description']),
              style: const TextStyle(fontSize: 12.5, color: Colors.grey),
              maxLines: 2, overflow: TextOverflow.ellipsis),
          ],
          const SizedBox(height: 10),
          Row(children: [
            Text(timeAgo(book['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const Spacer(),
            OutlinedButton.icon(
              onPressed: () => _runDialog(context),
              icon: const Icon(Icons.play_arrow, size: 14),
              label: const Text('Run', style: TextStyle(fontSize: 12)),
              style: OutlinedButton.styleFrom(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
                tapTargetSize: MaterialTapTargetSize.shrinkWrap),
            ),
            const SizedBox(width: 8),
            IconButton(
              icon: const Icon(Icons.delete_outline, color: Colors.redAccent, size: 18),
              onPressed: () async {
                if (await xConfirm(context, 'Delete Playbook', 'Delete "${str(book["name"])}"?')) {
                  final ok = await api.deletePlaybook(id);
                  if (context.mounted) xSnack(context, ok ? 'Deleted' : 'Failed', error: !ok);
                  onAction();
                }
              },
            ),
          ]),
        ]),
      ),
    );
  }

  void _runDialog(BuildContext context) {
    final id = book['id'] as int? ?? 0;
    showDialog(context: context, builder: (_) => AlertDialog(
      title: Text('Run: ${str(book["name"])}'),
      content: const Text('Trigger this playbook manually?'),
      actions: [
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
        FilledButton.icon(
          icon: const Icon(Icons.play_arrow, size: 16),
          label: const Text('Run'),
          onPressed: () async {
            Navigator.pop(context);
            final ok = await api.triggerPlaybook(id, {});
            if (context.mounted) xSnack(context, ok ? 'Playbook triggered' : 'Failed', error: !ok);
          },
        ),
      ],
    ));
  }

  String _triggerLabel(String t) => switch (t) {
    'alert'     => 'On Alert',
    'incident'  => 'On Incident',
    'scheduled' => 'Scheduled',
    _           => 'Manual',
  };
}

class _Tag extends StatelessWidget {
  final IconData icon;
  final String label;
  const _Tag(this.icon, this.label);

  @override
  Widget build(BuildContext context) => Row(mainAxisSize: MainAxisSize.min, children: [
    Icon(icon, size: 12, color: Colors.grey),
    const SizedBox(width: 4),
    Text(label, style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
  ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Approvals Screen
// ─────────────────────────────────────────────────────────────────────────────

class ApprovalsScreen extends StatefulWidget {
  final DashboardApi api;
  const ApprovalsScreen({super.key, required this.api});
  @override State<ApprovalsScreen> createState() => _ApprovalsState();
}

class _ApprovalsState extends State<ApprovalsScreen> {
  List _tasks   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _tasks = await widget.api.pendingApprovals();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_tasks.isEmpty) return const XEmptyState('No pending approvals', icon: Icons.approval_outlined);
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: _tasks.length,
        itemBuilder: (_, i) {
          // aq_requests — request_type/requested_action/requester/severity,
          // not the legacy agent-task shape (task_type/agent_id).
          final t  = _tasks[i] as Map<String,dynamic>;
          final id = t['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: Padding(
              padding: const EdgeInsets.all(14),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(child: Text(str(t['requested_action'] ?? t['request_type'], 'Request'),
                    style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700))),
                  if (t['is_emergency'] == true) const Padding(
                    padding: EdgeInsets.only(right: 6),
                    child: Icon(Icons.priority_high, size: 16, color: Color(0xFFEF4444))),
                  SevChip(str(t['severity'])),
                ]),
                const SizedBox(height: 4),
                Text('${str(t['target_asset'] ?? t['target_user'], '')}  ·  requested by ${str(t['requester'])}',
                  style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
                Text(timeAgo(t['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
                const SizedBox(height: 10),
                Row(children: [
                  Expanded(child: OutlinedButton.icon(
                    onPressed: () async {
                      final ok = await widget.api.approveTask(id);
                      if (context.mounted) xSnack(context, ok ? 'Approved' : 'Failed', error: !ok);
                      _load();
                    },
                    icon: const Icon(Icons.check, size: 14, color: Color(0xFF22C55E)),
                    label: const Text('Approve', style: TextStyle(color: Color(0xFF22C55E), fontSize: 13)),
                  )),
                  const SizedBox(width: 8),
                  Expanded(child: OutlinedButton.icon(
                    onPressed: () async {
                      final ok = await widget.api.rejectTask(id, 'Rejected by admin');
                      if (context.mounted) xSnack(context, ok ? 'Rejected' : 'Failed', error: !ok);
                      _load();
                    },
                    icon: const Icon(Icons.close, size: 14, color: Color(0xFFEF4444)),
                    label: const Text('Reject', style: TextStyle(color: Color(0xFFEF4444), fontSize: 13)),
                  )),
                ]),
              ]),
            ),
          );
        },
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Scheduled Tasks Screen
// ─────────────────────────────────────────────────────────────────────────────

class ScheduledTasksScreen extends StatefulWidget {
  final DashboardApi api;
  const ScheduledTasksScreen({super.key, required this.api});
  @override State<ScheduledTasksScreen> createState() => _ScheduledTasksState();
}

class _ScheduledTasksState extends State<ScheduledTasksScreen> {
  List _tasks   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _tasks = await widget.api.scheduledTasks();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  void _showCreate() {
    final nameCtrl  = TextEditingController();
    final cronCtrl  = TextEditingController(text: '0 * * * *');
    String taskType = 'collect_processes';
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('New Scheduled Task'),
            const SizedBox(height: 16),
            xField(nameCtrl, 'Task Name'),
            const SizedBox(height: 10),
            xField(cronCtrl, 'Cron Schedule (e.g. 0 * * * *)'),
            const SizedBox(height: 10),
            xDropdown('Task Type', taskType, const ['collect_processes', 'collect_packages', 'vulnerability_scan', 'collect_connections'], (v) => ss(() => taskType = v!)),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.schedule, size: 16),
              label: const Text('Schedule Task'),
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createScheduledTask({
                  'name': nameCtrl.text, 'cron_expr': cronCtrl.text, 'schedule_type': 'cron',
                  'task_type': taskType, 'category': 'security_operations', 'enabled': true,
                });
                if (context.mounted) xSnack(context, ok ? 'Scheduled' : 'Failed', error: !ok);
                _load();
              },
            )),
          ]),
        ),
      )),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.schedule),
        label: const Text('Schedule'),
      ),
      body: _tasks.isEmpty
        ? const XEmptyState('No scheduled tasks', icon: Icons.schedule_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
              itemCount: _tasks.length,
              itemBuilder: (_, i) {
                final t       = _tasks[i] as Map<String,dynamic>;
                final id      = t['id'] as int? ?? 0;
                final enabled = t['enabled'] == true;
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Container(
                      width: 38, height: 38,
                      decoration: BoxDecoration(
                        color: (enabled ? const Color(0xFF3B82F6) : Colors.grey).withValues(alpha: .1),
                        borderRadius: BorderRadius.circular(9)),
                      child: Icon(Icons.schedule, size: 18,
                        color: enabled ? const Color(0xFF3B82F6) : Colors.grey)),
                    title: Text(str(t['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Text('${str(t['cron_expr'])}  ·  ${str(t['task_type'])}  ·  ${t['run_count'] ?? 0} runs'),
                    trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                      Switch(
                        value: enabled,
                        onChanged: (v) async {
                          final ok = await widget.api.toggleScheduledTask(id, v);
                          if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                          _load();
                        },
                      ),
                      IconButton(
                        icon: const Icon(Icons.play_arrow, size: 18, color: Color(0xFF22C55E)),
                        onPressed: () async {
                          final ok = await widget.api.runScheduledTask(id);
                          if (context.mounted) xSnack(context, ok ? 'Task triggered' : 'Failed', error: !ok);
                        },
                      ),
                    ]),
                  ),
                );
              },
            ),
          ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// DFIR Screen
// ─────────────────────────────────────────────────────────────────────────────

class DFIRScreen extends StatefulWidget {
  final DashboardApi api;
  const DFIRScreen({super.key, required this.api});
  @override State<DFIRScreen> createState() => _DFIRState();
}

class _DFIRState extends State<DFIRScreen> {
  List _collections = [];
  List _agents      = [];
  bool _loading     = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.dfirCollections(), widget.api.agents()]);
    if (!mounted) return;
    setState(() { _collections = res[0]; _agents = res[1]; _loading = false; });
  }

  void _startCollection() {
    int? agentId = _agents.isNotEmpty ? ((_agents.first as Map)['id'] as int?) : null;
    String type = 'triage';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New DFIR Collection'),
          DropdownButtonFormField<int>(
            initialValue: agentId,
            decoration: const InputDecoration(labelText: 'Agent', isDense: true),
            items: _agents.map((a) {
              final m = a as Map<String,dynamic>;
              return DropdownMenuItem(value: m['id'] as int?, child: Text(str(m['hostname'])));
            }).toList(),
            onChanged: (v) => ss(() => agentId = v),
          ),
          const SizedBox(height: 10),
          xDropdown('Collection Type', type, ['triage','memory','disk','full'], (v) => ss(() => type = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: agentId == null ? null : () async {
              Navigator.pop(ctx);
              final ok = await widget.api.triggerDfir(agentId!, type);
              if (context.mounted) xSnack(context, ok ? 'Collection started' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Start Collection'),
          )),
        ]),
      )),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _collections.isEmpty
        ? const XEmptyState('No DFIR collections', icon: Icons.folder_zip_outlined)
        : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: _collections.length,
        itemBuilder: (_, i) {
          final col  = _collections[i] as Map<String,dynamic>;
          // models.ForensicCollection (models/dfir.go:8) has no
          // collection_type/type field — real fields are label and
          // agent_hostname (falls back to agent_id if hostname wasn't
          // joined in this response).
          final label = str(col['label'], 'Collection');
          final host  = str(col['agent_hostname'], 'Agent ${str(col['agent_id'])}');
          final st   = str(col['status']);
          final ok   = st == 'completed';
          final stCol = ok ? const Color(0xFF22C55E) : Colors.grey;
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: ListTile(
              leading: Container(
                width: 38, height: 38,
                decoration: BoxDecoration(
                  color: stCol.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(9)),
                child: Icon(Icons.folder_zip, size: 18, color: stCol)),
              title: Text('$label — $host',
                style: const TextStyle(fontWeight: FontWeight.w700)),
              subtitle: Row(children: [
                StatusChip(st),
                const SizedBox(width: 6),
                Text(timeAgo(col['created_at']),
                  style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ]),
              trailing: ok ? IconButton(
                icon: const Icon(Icons.download, size: 18),
                onPressed: () => xSnack(context, 'Download not available on mobile'),
              ) : null,
            ),
          );
        },
      ),
    ),
      floatingActionButton: FloatingActionButton(onPressed: _startCollection, child: const Icon(Icons.add)),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Quarantine Screen
// ─────────────────────────────────────────────────────────────────────────────

class QuarantineScreen extends StatefulWidget {
  final DashboardApi api;
  const QuarantineScreen({super.key, required this.api});
  @override State<QuarantineScreen> createState() => _QuarantineState();
}

class _QuarantineState extends State<QuarantineScreen> {
  List                 _files   = [];
  Map<String,dynamic>? _stats;
  bool                 _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.quarantine().then((r)      => _files = r),
      widget.api.quarantineStats().then((r) => _stats = r),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final stats = _stats ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Row(children: [
            Expanded(child: KpiCard(label: 'Active', value: str(stats['active_quarantine_sessions'] ?? _files.length),
              color: const Color(0xFFEF4444), icon: Icons.security)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Released', value: str(stats['released_assets'] ?? 0),
              color: const Color(0xFF22C55E), icon: Icons.lock_open)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Pending Approval', value: str(stats['pending_approvals'] ?? 0),
              color: const Color(0xFFF59E0B), icon: Icons.hourglass_top)),
          ]),
          const SizedBox(height: 16),
          SectionTitle('Quarantined Assets'),
          if (_files.isEmpty)
            const XEmptyState('No quarantined assets', icon: Icons.security_update_good_outlined)
          else
            ..._files.map((f) {
              // qe_items — asset_name/asset_type/status, not file_name/path.
              final file = f as Map<String,dynamic>;
              final id   = file['id'] as int? ?? 0;
              final active = str(file['status']) == 'active';
              return Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(10),
                  color: const Color(0xFFEF4444).withValues(alpha: .04),
                  border: Border.all(color: const Color(0xFFEF4444).withValues(alpha: .2))),
                child: Row(children: [
                  const Icon(Icons.insert_drive_file, color: Color(0xFFEF4444), size: 20),
                  const SizedBox(width: 12),
                  Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(str(file['asset_name'], 'Unknown'),
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                      maxLines: 1, overflow: TextOverflow.ellipsis),
                    Text('${str(file['asset_type'])}  ·  ${str(file['quarantine_id'])}  ·  ${timeAgo(file['created_at'])}',
                      style: const TextStyle(fontSize: 11, color: Colors.grey)),
                  ])),
                  if (active) TextButton(
                    onPressed: () async {
                      if (await xConfirm(context, 'Release Asset', 'Release from quarantine?')) {
                        final ok = await widget.api.releaseQuarantine(id);
                        if (context.mounted) xSnack(context, ok ? 'Released' : 'Failed', error: !ok);
                        _load();
                      }
                    },
                    child: const Text('Release', style: TextStyle(fontSize: 12)),
                  ) else StatusChip(str(file['status'])),
                ]),
              );
            }),
        ],
      ),
    );
  }
}

