import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── Cases ─────────────────────────────────────────────────────────────────────

class CasesScreen extends StatefulWidget {
  final DashboardApi api;
  const CasesScreen({super.key, required this.api});
  @override State<CasesScreen> createState() => _CasesState();
}

class _CasesState extends State<CasesScreen> {
  List _cases = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.cases();
    if (!mounted) return;
    setState(() { _cases = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _cases.isEmpty ? const XEmptyState('No cases') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _cases.length,
          itemBuilder: (_, i) {
            final c  = _cases[i] as Map<String,dynamic>;
            final id = c['id'] as int? ?? 0;
            return Card(
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                leading: SevChip(str(c['severity'])),
                title: Text(str(c['title'] ?? 'Case $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
                subtitle: Text('${str(c['status']).toUpperCase()}  ·  ${timeAgo(c['created_at'])}', style: const TextStyle(fontSize: 11)),
                trailing: PopupMenuButton<String>(
                  onSelected: (v) async {
                    if (v == '__comment') { _addComment(id); return; }
                    if (v == 'delete') {
                      if (context.mounted && await xConfirm(context, 'Delete Case', 'Delete this case?')) { await widget.api.deleteCase(id); _load(); }
                      return;
                    }
                    await widget.api.updateCase(id, {'status': v});
                    _load();
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(value: 'in_progress', child: Text('In Progress')),
                    PopupMenuItem(value: 'closed',      child: Text('Close')),
                    PopupMenuDivider(),
                    PopupMenuItem(value: '__comment',   child: Text('Add Comment')),
                    PopupMenuItem(value: 'delete',      child: Text('Delete', style: TextStyle(color: Colors.red))),
                  ],
                ),
              ),
            );
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  void _addComment(int id) {
    final ctrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('Add Comment', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(ctrl, 'Comment', maxLines: 4),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async { Navigator.pop(ctx); await widget.api.addCaseComment(id, ctrl.text.trim()); xSnack(context, 'Comment added'); },
            child: const Text('Save'),
          )),
        ]),
      ),
    );
  }

  void _create() {
    final titleCtrl = TextEditingController();
    final descCtrl  = TextEditingController();
    String sev = 'medium';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Case', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(titleCtrl, 'Title'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description', maxLines: 3),
          const SizedBox(height: 10),
          xDropdown('Severity', sev, ['critical','high','medium','low'], (v) => ss(() => sev = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createCase({'title': titleCtrl.text.trim(), 'description': descCtrl.text.trim(), 'severity': sev, 'status': 'open'});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Playbooks ─────────────────────────────────────────────────────────────────

class PlaybooksScreen extends StatefulWidget {
  final DashboardApi api;
  const PlaybooksScreen({super.key, required this.api});
  @override State<PlaybooksScreen> createState() => _PlaybooksState();
}

class _PlaybooksState extends State<PlaybooksScreen> {
  List _books = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.playbooks();
    if (!mounted) return;
    setState(() { _books = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _books.isEmpty ? const XEmptyState('No playbooks') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _books.length,
          itemBuilder: (_, i) {
            final b = _books[i] as Map<String,dynamic>;
            final id      = b['id'] as int? ?? 0;
            final enabled = b['is_enabled'] as bool? ?? b['enabled'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.play_circle, color: enabled ? Colors.blue : Colors.grey),
              title: Text(str(b['name'])),
              subtitle: Text('${str(b['trigger_type'] ?? '')}  ·  ${b['execution_count'] ?? 0} runs  ·  ${timeAgo(b['last_executed_at'])}'),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'toggle') { enabled ? await widget.api.disablePlaybook(id) : await widget.api.enablePlaybook(id); _load(); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Playbook', 'Delete this playbook?')) { await widget.api.deletePlaybook(id); _load(); }
                  }
                },
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  void _create() {
    final nameCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    String trigger = 'manual';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Playbook', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description', maxLines: 2),
          const SizedBox(height: 10),
          xDropdown('Trigger', trigger, ['manual','alert','incident','scheduled'], (v) => ss(() => trigger = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createPlaybook({'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim(), 'trigger_type': trigger});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Approval Queue ────────────────────────────────────────────────────────────

class ApprovalQueueScreen extends StatefulWidget {
  final DashboardApi api;
  const ApprovalQueueScreen({super.key, required this.api});
  @override State<ApprovalQueueScreen> createState() => _ApprovalQueueState();
}

class _ApprovalQueueState extends State<ApprovalQueueScreen> {
  List _tasks = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.pendingApprovals();
    if (!mounted) return;
    setState(() { _tasks = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_tasks.isEmpty) return const Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      Icon(Icons.check_circle, size: 48, color: Colors.green),
      SizedBox(height: 12),
      Text('No pending approvals', style: TextStyle(color: Colors.grey)),
    ]));
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _tasks.length,
        itemBuilder: (_, i) {
          final t  = _tasks[i] as Map<String,dynamic>;
          final id = t['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(str(t['task_type']), style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14)),
                const SizedBox(height: 4),
                Text('Agent: ${str(t['agent_id'] ?? t['hostname'])}  ·  ${timeAgo(t['created_at'])}', style: const TextStyle(fontSize: 12, color: Colors.grey)),
                if (t['payload'] != null) Text('Payload: ${t['payload'].toString()}', style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 1),
                const SizedBox(height: 10),
                Row(children: [
                  Expanded(child: OutlinedButton(
                    style: OutlinedButton.styleFrom(foregroundColor: Colors.red),
                    onPressed: () async { await widget.api.rejectTask(id, 'Rejected from mobile admin'); _load(); },
                    child: const Text('Reject'),
                  )),
                  const SizedBox(width: 10),
                  Expanded(child: FilledButton(
                    onPressed: () async { await widget.api.approveTask(id); _load(); },
                    child: const Text('Approve'),
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

// ── Vulnerabilities ───────────────────────────────────────────────────────────

class VulnerabilitiesScreen extends StatefulWidget {
  final DashboardApi api;
  const VulnerabilitiesScreen({super.key, required this.api});
  @override State<VulnerabilitiesScreen> createState() => _VulnerabilitiesState();
}

class _VulnerabilitiesState extends State<VulnerabilitiesScreen> {
  List _agents = [], _vulns = [];
  bool _loading = true;
  int? _agentId;

  @override void initState() { super.initState(); _init(); }

  Future<void> _init() async {
    final agents = await widget.api.agents();
    if (!mounted) return;
    setState(() { _agents = agents; if (agents.isNotEmpty) _agentId = (agents.first as Map)['id'] as int?; });
    if (_agentId != null) _load();
  }

  Future<void> _load() async {
    if (_agentId == null) return;
    setState(() => _loading = true);
    final r = await widget.api.agentVulnerabilities(_agentId!);
    if (!mounted) return;
    setState(() { _vulns = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      if (_agents.isNotEmpty)
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
          child: DropdownButtonFormField<int>(
            value: _agentId,
            decoration: const InputDecoration(labelText: 'Agent', border: OutlineInputBorder(), isDense: true),
            items: _agents.map((a) { final m = a as Map<String,dynamic>; return DropdownMenuItem<int>(value: m['id'] as int?, child: Text(str(m['hostname']), style: const TextStyle(fontSize: 13))); }).toList(),
            onChanged: (v) { setState(() => _agentId = v); _load(); },
          ),
        ),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else if (_vulns.isEmpty) const Expanded(child: XEmptyState('No vulnerabilities found'))
      else Expanded(child: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.all(8),
          itemCount: _vulns.length,
          itemBuilder: (_, i) {
            final v = _vulns[i] as Map<String,dynamic>;
            return Card(child: ListTile(
              leading: SevChip(str(v['severity'])),
              title: Text(str(v['cve_id'] ?? v['cve'] ?? v['name'])),
              subtitle: Text('${str(v['package_name'] ?? v['component'] ?? '')}  ·  Score: ${str(v['cvss_score'] ?? v['score'] ?? '')}'),
              trailing: StatusChip(str(v['patch_status'] ?? v['status'] ?? 'open')),
            ));
          },
        ),
      )),
    ]);
  }
}

// ── Vuln Queue ────────────────────────────────────────────────────────────────

class VulnQueueScreen extends StatefulWidget {
  final DashboardApi api;
  const VulnQueueScreen({super.key, required this.api});
  @override State<VulnQueueScreen> createState() => _VulnQueueState();
}

class _VulnQueueState extends State<VulnQueueScreen> {
  List _vulns = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.vulnQueue();
    if (!mounted) return;
    setState(() { _vulns = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _vulns.isEmpty ? const XEmptyState('No prioritized vulnerabilities') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _vulns.length,
          itemBuilder: (_, i) {
            final v  = _vulns[i] as Map<String,dynamic>;
            final id = v['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: SevChip(str(v['severity'])),
              title: Text(str(v['cve_id'] ?? v['cve'])),
              subtitle: Text('${str(v['hostname'] ?? v['agent_id'])}  ·  ${str(v['package_name'] ?? '')}  ·  CVSS: ${str(v['cvss_score'] ?? '')}'),
              trailing: PopupMenuButton<String>(
                onSelected: (v2) async {
                  await widget.api.updatePatchStatus(id, v2);
                  _load();
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'patching',  child: Text('Patching')),
                  PopupMenuItem(value: 'patched',   child: Text('Mark Patched')),
                  PopupMenuItem(value: 'wontfix',   child: Text("Won't Fix")),
                  PopupMenuItem(value: 'exception', child: Text('Exception')),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async { await widget.api.refreshVulnPriorities(); xSnack(context, 'Priority refresh triggered'); },
        icon: const Icon(Icons.refresh),
        label: const Text('Refresh Priorities'),
      ),
    );
  }
}

// ── Quarantine ────────────────────────────────────────────────────────────────

class QuarantineScreen extends StatefulWidget {
  final DashboardApi api;
  const QuarantineScreen({super.key, required this.api});
  @override State<QuarantineScreen> createState() => _QuarantineState();
}

class _QuarantineState extends State<QuarantineScreen> {
  List _files = [];
  Map<String,dynamic>? _stats;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.quarantine(), widget.api.quarantineStats()]);
    if (!mounted) return;
    setState(() { _files = res[0] as List; _stats = res[1] as Map<String,dynamic>?; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final s = _stats ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(8),
        children: [
          if (s.isNotEmpty) StatRow([
            ('Total Files', str(s['total'] ?? s['count'] ?? 0), Colors.orange),
            ('Total Size',  str(s['total_size_mb'] != null ? '${s['total_size_mb']}MB' : s['size'] ?? 0), Colors.blue),
          ]),
          if (_files.isEmpty) const Padding(padding: EdgeInsets.only(top: 40), child: XEmptyState('No quarantined files'))
          else ..._files.map((f) {
            final file = f as Map<String,dynamic>;
            final id   = file['id'] as int? ?? 0;
            return Card(
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                leading: const Icon(Icons.lock, color: Colors.orange),
                title: Text(str(file['file_name'] ?? file['name']), style: const TextStyle(fontSize: 13)),
                subtitle: Text('${str(file['hostname'] ?? '')}  ·  ${str(file['sha256'] ?? file['hash'] ?? '').substring(0, (str(file['sha256'] ?? file['hash'] ?? '')).length.clamp(0, 12))}  ·  ${timeAgo(file['quarantined_at'] ?? file['created_at'])}'),
                trailing: TextButton(
                  onPressed: () async {
                    if (await xConfirm(context, 'Release File', 'Release this file from quarantine?')) { await widget.api.releaseQuarantine(id); _load(); }
                  },
                  child: const Text('Release'),
                ),
              ),
            );
          }),
        ],
      ),
    );
  }
}

// ── Firewall ──────────────────────────────────────────────────────────────────

class FirewallScreen extends StatefulWidget {
  final DashboardApi api;
  const FirewallScreen({super.key, required this.api});
  @override State<FirewallScreen> createState() => _FirewallState();
}

class _FirewallState extends State<FirewallScreen> {
  List _rules = [];
  Map<String,dynamic>? _stats;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.firewallRules(), widget.api.firewallStats()]);
    if (!mounted) return;
    setState(() { _rules = res[0] as List; _stats = res[1] as Map<String,dynamic>?; _loading = false; });
  }

  Color _actColor(String a) => switch(a.toLowerCase()) { 'allow' => Colors.green, 'deny' || 'drop' || 'block' => Colors.red, _ => Colors.grey };

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final s = _stats ?? {};
    return Scaffold(
      body: RefreshIndicator(
        onRefresh: _load,
        child: ListView(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          children: [
            if (s.isNotEmpty) StatRow([
              ('Total Rules', str(s['total_rules'] ?? s['total'] ?? _rules.length), Colors.blue),
              ('Blocked Hits', str(s['blocked_hits'] ?? s['block_count'] ?? 0), Colors.red),
            ]),
            ..._rules.map((r) {
              final rule = r as Map<String,dynamic>;
              final id   = rule['id'] as int? ?? 0;
              final act  = str(rule['action']);
              return Card(
                margin: const EdgeInsets.only(bottom: 4),
                child: ListTile(
                  leading: Icon(act.toLowerCase() == 'allow' ? Icons.check_circle_outline : Icons.block, color: _actColor(act)),
                  title: Text(
                    '${str(rule['src_ip'] ?? 'any')}:${str(rule['src_port'] ?? '*')} → ${str(rule['dst_ip'] ?? 'any')}:${str(rule['dst_port'] ?? '*')}',
                    style: const TextStyle(fontFamily: 'monospace', fontSize: 11),
                  ),
                  subtitle: Text('${act.toUpperCase()}  ·  ${str(rule['protocol'] ?? 'any').toUpperCase()}  ·  ${str(rule['description'] ?? '')}', maxLines: 1),
                  trailing: PopupMenuButton<String>(
                    onSelected: (v) async {
                      if (v == 'delete') {
                        if (context.mounted && await xConfirm(context, 'Delete Rule', 'Delete this firewall rule?')) { await widget.api.deleteFirewallRule(id); _load(); }
                      }
                    },
                    itemBuilder: (_) => const [
                      PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                    ],
                  ),
                ),
              );
            }),
          ],
        ),
      ),
      floatingActionButton: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          FloatingActionButton.small(
            heroTag: 'fw_sync',
            onPressed: () async { await widget.api.syncFirewall(); xSnack(context, 'Sync triggered'); },
            tooltip: 'Sync',
            child: const Icon(Icons.sync),
          ),
          const SizedBox(height: 8),
          FloatingActionButton(heroTag: 'fw_add', onPressed: _create, child: const Icon(Icons.add)),
        ],
      ),
    );
  }

  void _create() {
    final srcCtrl = TextEditingController();
    final dstCtrl = TextEditingController();
    final srcPortCtrl = TextEditingController();
    final dstPortCtrl = TextEditingController();
    final descCtrl    = TextEditingController();
    String action = 'deny', proto = 'any';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => SingleChildScrollView(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Firewall Rule', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          Row(children: [
            Expanded(child: xField(srcCtrl, 'Src IP')),
            const SizedBox(width: 8),
            Expanded(child: xField(srcPortCtrl, 'Src Port')),
          ]),
          const SizedBox(height: 10),
          Row(children: [
            Expanded(child: xField(dstCtrl, 'Dst IP')),
            const SizedBox(width: 8),
            Expanded(child: xField(dstPortCtrl, 'Dst Port')),
          ]),
          const SizedBox(height: 10),
          Row(children: [
            Expanded(child: xDropdown('Protocol', proto, ['any','tcp','udp','icmp'], (v) => ss(() => proto = v!))),
            const SizedBox(width: 8),
            Expanded(child: xDropdown('Action', action, ['deny','allow','drop'], (v) => ss(() => action = v!))),
          ]),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createFirewallRule({'src_ip': srcCtrl.text.trim(), 'dst_ip': dstCtrl.text.trim(), 'src_port': srcPortCtrl.text.trim(), 'dst_port': dstPortCtrl.text.trim(), 'protocol': proto, 'action': action, 'description': descCtrl.text.trim()});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Scheduled Tasks ───────────────────────────────────────────────────────────

class ScheduledTasksScreen extends StatefulWidget {
  final DashboardApi api;
  const ScheduledTasksScreen({super.key, required this.api});
  @override State<ScheduledTasksScreen> createState() => _ScheduledTasksState();
}

class _ScheduledTasksState extends State<ScheduledTasksScreen> {
  List _tasks = [], _agents = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.scheduledTasks(), widget.api.agents()]);
    if (!mounted) return;
    setState(() { _tasks = res[0]; _agents = res[1]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _tasks.isEmpty ? const XEmptyState('No scheduled tasks') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _tasks.length,
          itemBuilder: (_, i) {
            final t       = _tasks[i] as Map<String,dynamic>;
            final id      = t['id'] as int? ?? 0;
            final enabled = t['enabled'] as bool? ?? t['is_enabled'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.schedule, color: enabled ? Colors.green : Colors.grey),
              title: Text(str(t['name'])),
              subtitle: Text('${str(t['cron_expr'] ?? '')}  ·  ${str(t['task_type'])}  ·  Next: ${timeAgo(t['next_run_at'])}'),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'toggle') await widget.api.toggleScheduledTask(id);
                  if (v == 'run')    { await widget.api.runScheduledTask(id); xSnack(context, 'Task triggered'); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Task', 'Delete this scheduled task?')) await widget.api.deleteScheduledTask(id);
                  }
                  _load();
                },
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                  const PopupMenuItem(value: 'run',    child: Text('Run Now')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  void _create() {
    final nameCtrl = TextEditingController();
    final cronCtrl = TextEditingController(text: '0 * * * *');
    String taskType = 'collect_processes';
    int? agentId = _agents.isNotEmpty ? (_agents.first as Map)['id'] as int? : null;
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => SingleChildScrollView(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Scheduled Task', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(cronCtrl, 'Cron Expression'),
          const SizedBox(height: 10),
          xDropdown('Task Type', taskType, ['collect_processes','collect_connections','collect_packages','vulnerability_scan','collect_file_hashes'], (v) => ss(() => taskType = v!)),
          if (_agents.isNotEmpty) ...[
            const SizedBox(height: 10),
            DropdownButtonFormField<int>(
              value: agentId,
              decoration: const InputDecoration(labelText: 'Agent', border: OutlineInputBorder()),
              items: _agents.map((a) { final m = a as Map<String,dynamic>; return DropdownMenuItem<int>(value: m['id'] as int?, child: Text(str(m['hostname']))); }).toList(),
              onChanged: (v) => ss(() => agentId = v),
            ),
          ],
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createScheduledTask({'name': nameCtrl.text.trim(), 'task_type': taskType, 'agent_id': agentId ?? 0, 'cron_expr': cronCtrl.text.trim(), 'payload': {}});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── DFIR ──────────────────────────────────────────────────────────────────────

class DFIRScreen extends StatefulWidget {
  final DashboardApi api;
  const DFIRScreen({super.key, required this.api});
  @override State<DFIRScreen> createState() => _DFIRState();
}

class _DFIRState extends State<DFIRScreen> {
  List _collections = [], _agents = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.dfirCollections(), widget.api.agents()]);
    if (!mounted) return;
    setState(() { _collections = res[0]; _agents = res[1]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _collections.isEmpty ? const XEmptyState('No forensic collections') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _collections.length,
          itemBuilder: (_, i) {
            final c = _collections[i] as Map<String,dynamic>;
            return Card(child: ListTile(
              leading: Icon(Icons.folder_copy, color: statusColor(str(c['status']))),
              title: Text(str(c['collection_type'] ?? c['type'] ?? 'Collection ${c['id']}')),
              subtitle: Text('${str(c['hostname'] ?? c['agent_id'])}  ·  ${str(c['status'])}  ·  ${timeAgo(c['created_at'])}'),
              trailing: Text('${c['artifact_count'] ?? 0} artifacts', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _trigger, child: const Icon(Icons.add)),
    );
  }

  void _trigger() {
    if (_agents.isEmpty) { xSnack(context, 'No agents available', error: true); return; }
    int? agentId = (_agents.first as Map)['id'] as int?;
    String type = 'full';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('Trigger Forensic Collection', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          DropdownButtonFormField<int>(
            value: agentId,
            decoration: const InputDecoration(labelText: 'Agent', border: OutlineInputBorder()),
            items: _agents.map((a) { final m = a as Map<String,dynamic>; return DropdownMenuItem<int>(value: m['id'] as int?, child: Text(str(m['hostname']))); }).toList(),
            onChanged: (v) => ss(() => agentId = v),
          ),
          const SizedBox(height: 10),
          xDropdown('Collection Type', type, ['full','memory','disk','network','logs'], (v) => ss(() => type = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.triggerDfir(agentId ?? 0, type);
              xSnack(context, 'Collection triggered');
              _load();
            },
            child: const Text('Trigger'),
          )),
        ]),
      )),
    );
  }
}

// ── Script Runner ─────────────────────────────────────────────────────────────

class ScriptRunnerScreen extends StatefulWidget {
  final DashboardApi api;
  const ScriptRunnerScreen({super.key, required this.api});
  @override State<ScriptRunnerScreen> createState() => _ScriptRunnerState();
}

class _ScriptRunnerState extends State<ScriptRunnerScreen> {
  List _agents = [], _templates = [];
  int? _agentId;
  String _interpreter = 'bash';
  final _scriptCtrl = TextEditingController();
  String _output = '';
  bool _running = false;

  @override void initState() { super.initState(); _init(); }
  @override void dispose() { _scriptCtrl.dispose(); super.dispose(); }

  Future<void> _init() async {
    final res = await Future.wait([widget.api.agents(), widget.api.scriptTemplates()]);
    if (!mounted) return;
    setState(() {
      _agents    = res[0];
      _templates = res[1];
      if (_agents.isNotEmpty) _agentId = (_agents.first as Map)['id'] as int?;
    });
  }

  Future<void> _run() async {
    if (_agentId == null || _scriptCtrl.text.trim().isEmpty) return;
    setState(() { _running = true; _output = ''; });
    final r = await widget.api.runScript(_agentId!, _scriptCtrl.text.trim(), _interpreter);
    if (!mounted) return;
    setState(() {
      _running = false;
      _output  = r != null ? (r['output'] ?? r['result'] ?? r['task_id'] ?? r.toString()) : 'Error';
    });
  }

  @override
  Widget build(BuildContext context) {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        // Agent + interpreter
        Row(children: [
          Expanded(
            flex: 2,
            child: _agents.isEmpty ? const Text('No agents') : DropdownButtonFormField<int>(
              value: _agentId,
              decoration: const InputDecoration(labelText: 'Target Agent', border: OutlineInputBorder(), isDense: true),
              items: _agents.map((a) { final m = a as Map<String,dynamic>; return DropdownMenuItem<int>(value: m['id'] as int?, child: Text(str(m['hostname']), style: const TextStyle(fontSize: 12))); }).toList(),
              onChanged: (v) => setState(() => _agentId = v),
            ),
          ),
          const SizedBox(width: 8),
          Expanded(child: DropdownButtonFormField<String>(
            value: _interpreter,
            decoration: const InputDecoration(labelText: 'Shell', border: OutlineInputBorder(), isDense: true),
            items: ['bash','sh','powershell','python3','python'].map((s) => DropdownMenuItem(value: s, child: Text(s))).toList(),
            onChanged: (v) => setState(() => _interpreter = v!),
          )),
        ]),
        const SizedBox(height: 10),
        // Templates
        if (_templates.isNotEmpty) SizedBox(height: 36, child: ListView.separated(
          scrollDirection: Axis.horizontal,
          itemCount: _templates.length,
          separatorBuilder: (_, __) => const SizedBox(width: 6),
          itemBuilder: (_, i) {
            final t = _templates[i] as Map<String,dynamic>;
            return ActionChip(
              label: Text(str(t['name']), style: const TextStyle(fontSize: 11)),
              onPressed: () => setState(() => _scriptCtrl.text = str(t['content'] ?? t['script'] ?? '')),
            );
          },
        )),
        const SizedBox(height: 10),
        // Script editor
        Container(
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceVariant,
            borderRadius: BorderRadius.circular(8),
          ),
          child: TextField(
            controller: _scriptCtrl,
            maxLines: 12,
            style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
            decoration: const InputDecoration(
              hintText: '#!/bin/bash\n# Script here…',
              border: InputBorder.none,
              contentPadding: EdgeInsets.all(12),
            ),
          ),
        ),
        const SizedBox(height: 10),
        FilledButton.icon(
          onPressed: _running ? null : _run,
          icon: _running ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white)) : const Icon(Icons.play_arrow),
          label: Text(_running ? 'Running…' : 'Run Script'),
        ),
        if (_output.isNotEmpty) ...[
          const SizedBox(height: 12),
          const Text('OUTPUT', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
          const SizedBox(height: 6),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(color: Colors.black87, borderRadius: BorderRadius.circular(8)),
            child: SelectableText(_output, style: const TextStyle(fontFamily: 'monospace', fontSize: 11, color: Colors.greenAccent)),
          ),
        ],
      ]),
    );
  }
}
