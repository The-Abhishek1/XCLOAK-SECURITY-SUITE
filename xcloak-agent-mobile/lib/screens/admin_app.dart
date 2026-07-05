import 'package:flutter/material.dart';

import '../services/dashboard_api.dart';
import '../services/secure_storage.dart';

// ── Admin App Shell ───────────────────────────────────────────────────────────
//
// Full NGFW dashboard on mobile. Only available when an Admin API Key is
// stored. Navigates via a drawer. Each section is a StatefulWidget that
// loads lazily when first visited.

class AdminApp extends StatefulWidget {
  final DashboardApi api;
  const AdminApp({super.key, required this.api});

  @override
  State<AdminApp> createState() => _AdminAppState();
}

class _AdminAppState extends State<AdminApp> {
  int _section = 0;
  final _scaffoldKey = GlobalKey<ScaffoldState>();

  static const _sections = [
    (Icons.dashboard,          'Overview'),
    (Icons.notifications,      'Alerts'),
    (Icons.bolt,               'Incidents'),
    (Icons.computer,           'Agents'),
    (Icons.smartphone,         'MDM Devices'),
    (Icons.folder_special,     'Cases'),
    (Icons.check_circle,       'Approvals'),
    (Icons.shield,             'Firewall'),
    (Icons.play_circle_filled, 'Playbooks'),
  ];

  Widget _buildSection() {
    final api = widget.api;
    switch (_section) {
      case 0:  return OverviewSection(api: api);
      case 1:  return AlertsSection(api: api);
      case 2:  return IncidentsSection(api: api);
      case 3:  return AgentsSection(api: api);
      case 4:  return MDMSection(api: api);
      case 5:  return CasesSection(api: api);
      case 6:  return ApprovalsSection(api: api);
      case 7:  return FirewallSection(api: api);
      case 8:  return PlaybooksSection(api: api);
      default: return OverviewSection(api: api);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      key: _scaffoldKey,
      appBar: AppBar(
        title: Text(_sections[_section].$2),
        leading: IconButton(
          icon: const Icon(Icons.menu),
          onPressed: () => _scaffoldKey.currentState?.openDrawer(),
        ),
      ),
      drawer: Drawer(
        child: Column(
          children: [
            DrawerHeader(
              decoration: BoxDecoration(color: Theme.of(context).colorScheme.primary),
              child: const Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.end,
                children: [
                  Icon(Icons.security, color: Colors.white, size: 36),
                  SizedBox(height: 8),
                  Text('XCloak Admin',
                      style: TextStyle(color: Colors.white, fontSize: 18, fontWeight: FontWeight.bold)),
                  Text('NGFW Dashboard', style: TextStyle(color: Colors.white70, fontSize: 12)),
                ],
              ),
            ),
            Expanded(
              child: ListView.builder(
                padding: EdgeInsets.zero,
                itemCount: _sections.length,
                itemBuilder: (ctx, i) {
                  final s = _sections[i];
                  return ListTile(
                    leading: Icon(s.$1, color: _section == i ? Theme.of(context).colorScheme.primary : null),
                    title: Text(s.$2),
                    selected: _section == i,
                    selectedTileColor: Theme.of(context).colorScheme.primary.withOpacity(0.1),
                    onTap: () {
                      setState(() => _section = i);
                      Navigator.pop(ctx);
                    },
                  );
                },
              ),
            ),
            const Divider(height: 1),
            ListTile(
              leading: const Icon(Icons.logout, color: Colors.red),
              title: const Text('Switch to Agent Mode', style: TextStyle(color: Colors.red)),
              onTap: () async {
                Navigator.pop(context);
                await SecureStore.removeApiKey();
                if (context.mounted) {
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Switched to agent-only mode. Restart the app to apply.')),
                  );
                }
              },
            ),
            const SizedBox(height: 8),
          ],
        ),
      ),
      body: _buildSection(),
    );
  }
}

// ── Shared helpers ────────────────────────────────────────────────────────────

String timeAgo(String? ts) {
  if (ts == null || ts.isEmpty) return 'never';
  try {
    final d    = DateTime.parse(ts).toLocal();
    final diff = DateTime.now().difference(d);
    if (diff.inSeconds < 60)  return 'just now';
    if (diff.inMinutes < 60)  return '${diff.inMinutes}m ago';
    if (diff.inHours < 24)    return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  } catch (_) { return ts; }
}

Color severityColor(BuildContext ctx, String s) {
  switch (s.toLowerCase()) {
    case 'critical': return Colors.red;
    case 'high':     return Colors.orange;
    case 'medium':   return Colors.yellow.shade700;
    default:         return Colors.grey;
  }
}

Color statusColor(String s) {
  switch (s.toLowerCase()) {
    case 'open':     return Colors.orange;
    case 'online':   return Colors.green;
    case 'active':   return Colors.green;
    case 'resolved': return Colors.grey;
    case 'closed':   return Colors.grey;
    case 'blocked':  return Colors.red;
    default:         return Colors.grey;
  }
}

Widget _statCard(String label, String value, Color color) => Card(
  child: Padding(
    padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        Text(value, style: TextStyle(fontSize: 22, fontWeight: FontWeight.bold, color: color)),
        Text(label,  style: const TextStyle(fontSize: 11, color: Colors.grey)),
      ],
    ),
  ),
);

// ── Overview section ──────────────────────────────────────────────────────────

class OverviewSection extends StatefulWidget {
  final DashboardApi api;
  const OverviewSection({super.key, required this.api});
  @override State<OverviewSection> createState() => _OverviewSectionState();
}

class _OverviewSectionState extends State<OverviewSection> {
  Map<String, dynamic>? _overview;
  List<dynamic> _recentAlerts = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final results = await Future.wait([
      widget.api.getOverview(),
      widget.api.getAlerts(perPage: 5),
    ]);
    if (!mounted) return;
    setState(() {
      _overview     = results[0] as Map<String, dynamic>?;
      _recentAlerts = results[1] as List<dynamic>;
      _loading      = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    final ov = _overview ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          GridView.count(
            crossAxisCount: 2,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            childAspectRatio: 2.0,
            mainAxisSpacing: 8,
            crossAxisSpacing: 8,
            children: [
              _statCard('Agents Online',   '${ov['agents_online']     ?? ov['online_agents']  ?? 0}', Colors.green),
              _statCard('Open Alerts',     '${ov['open_alerts']       ?? ov['active_alerts']  ?? 0}', Colors.orange),
              _statCard('Critical Alerts', '${ov['critical_alerts']   ?? 0}',                         Colors.red),
              _statCard('Open Incidents',  '${ov['active_incidents']  ?? ov['open_incidents'] ?? 0}', Colors.blue),
              _statCard('Open Cases',      '${ov['open_cases']        ?? 0}',                         Colors.purple),
              _statCard('Pending Approvals','${ov['pending_approvals'] ?? 0}',                        Colors.amber),
            ],
          ),
          const SizedBox(height: 16),
          if (_recentAlerts.isNotEmpty) ...[
            const Text('RECENT ALERTS', style: TextStyle(fontSize: 11, fontWeight: FontWeight.bold, letterSpacing: 1.2, color: Colors.grey)),
            const SizedBox(height: 6),
            ..._recentAlerts.take(5).map((a) {
              final m = a as Map<String, dynamic>;
              return Card(
                margin: const EdgeInsets.only(bottom: 6),
                child: ListTile(
                  dense: true,
                  leading: CircleAvatar(
                    radius: 5,
                    backgroundColor: severityColor(context, (m['severity'] ?? '').toString()),
                  ),
                  title: Text(
                    (m['rule_name'] ?? m['message'] ?? 'Alert').toString(),
                    maxLines: 1, overflow: TextOverflow.ellipsis,
                    style: const TextStyle(fontSize: 13),
                  ),
                  subtitle: Text(
                    '${(m['severity'] ?? '').toString().toUpperCase()}  ·  ${timeAgo(m['created_at']?.toString())}',
                    style: const TextStyle(fontSize: 11),
                  ),
                ),
              );
            }),
          ],
        ],
      ),
    );
  }
}

// ── Alerts section ────────────────────────────────────────────────────────────

class AlertsSection extends StatefulWidget {
  final DashboardApi api;
  const AlertsSection({super.key, required this.api});
  @override State<AlertsSection> createState() => _AlertsSectionState();
}

class _AlertsSectionState extends State<AlertsSection> {
  List<dynamic> _alerts = [];
  bool _loading = true;
  String _sev   = '';
  String _stat  = '';

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getAlerts(severity: _sev, status: _stat, perPage: 50);
    if (!mounted) return;
    setState(() { _alerts = r; _loading = false; });
  }

  void _setFilter(String sev, String stat) {
    setState(() { _sev = sev; _stat = stat; });
    _load();
  }

  Future<void> _ack(Map<String, dynamic> a) async {
    await widget.api.acknowledgeAlert(a['id'] as int);
    _load();
  }

  Future<void> _resolve(Map<String, dynamic> a) async {
    await widget.api.resolveAlert(a['id'] as int);
    _load();
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        // Filter row
        SingleChildScrollView(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 0),
          child: Row(
            children: [
              for (final f in [('', ''), ('critical', ''), ('high', ''), ('medium', ''), ('', 'open')])
                Padding(
                  padding: const EdgeInsets.only(right: 6),
                  child: FilterChip(
                    label: Text(f.$1.isNotEmpty ? f.$1 : f.$2.isNotEmpty ? f.$2 : 'All'),
                    selected: _sev == f.$1 && _stat == f.$2,
                    onSelected: (_) => _setFilter(f.$1, f.$2),
                  ),
                ),
            ],
          ),
        ),
        if (_loading)
          const Expanded(child: Center(child: CircularProgressIndicator()))
        else if (_alerts.isEmpty)
          const Expanded(child: Center(child: Text('No alerts', style: TextStyle(color: Colors.grey))))
        else
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: _alerts.length,
              itemBuilder: (_, i) {
                final a   = _alerts[i] as Map<String, dynamic>;
                final sev = (a['severity'] ?? '').toString();
                final sta = (a['status']   ?? '').toString();
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: CircleAvatar(
                        radius: 6,
                        backgroundColor: severityColor(context, sev)),
                    title: Text(
                        (a['rule_name'] ?? a['message'] ?? 'Alert').toString(),
                        maxLines: 2, overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                    subtitle: Text(
                        '${sev.toUpperCase()}  ·  ${timeAgo(a['created_at']?.toString())}'
                        '${a['hostname'] != null ? "  ·  ${a['hostname']}" : ""}',
                        style: const TextStyle(fontSize: 11)),
                    trailing: sta == 'open'
                        ? PopupMenuButton<String>(
                            onSelected: (v) { if (v == 'ack') _ack(a); else _resolve(a); },
                            itemBuilder: (_) => const [
                              PopupMenuItem(value: 'ack',     child: Text('Acknowledge')),
                              PopupMenuItem(value: 'resolve', child: Text('Resolve')),
                            ],
                          )
                        : Text(sta, style: const TextStyle(fontSize: 11, color: Colors.grey)),
                  ),
                );
              },
            ),
          ),
      ],
    );
  }
}

// ── Incidents section ─────────────────────────────────────────────────────────

class IncidentsSection extends StatefulWidget {
  final DashboardApi api;
  const IncidentsSection({super.key, required this.api});
  @override State<IncidentsSection> createState() => _IncidentsSectionState();
}

class _IncidentsSectionState extends State<IncidentsSection> {
  List<dynamic> _incidents = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getIncidents(perPage: 50);
    if (!mounted) return;
    setState(() { _incidents = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_incidents.isEmpty) return const Center(child: Text('No incidents', style: TextStyle(color: Colors.grey)));

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _incidents.length,
        itemBuilder: (_, i) {
          final inc = _incidents[i] as Map<String, dynamic>;
          final sta = (inc['status'] ?? '').toString();
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: ListTile(
              leading: Icon(Icons.bolt, color: statusColor(sta)),
              title: Text((inc['title'] ?? 'Incident ${inc['id']}').toString(),
                  maxLines: 1, overflow: TextOverflow.ellipsis,
                  style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text(
                  '${sta.toUpperCase()}  ·  ${(inc['severity'] ?? '').toString().toUpperCase()}'
                  '  ·  ${timeAgo(inc['created_at']?.toString())}',
                  style: const TextStyle(fontSize: 11)),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  await widget.api.updateIncidentStatus(inc['id'] as int, v);
                  _load();
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'investigating', child: Text('Investigating')),
                  PopupMenuItem(value: 'contained',     child: Text('Contained')),
                  PopupMenuItem(value: 'resolved',      child: Text('Resolve')),
                  PopupMenuItem(value: 'closed',        child: Text('Close')),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Agents section ────────────────────────────────────────────────────────────

const _AGENT_TASKS = [
  ('collect_processes',   'Collect Processes'),
  ('collect_connections', 'Collect Connections'),
  ('collect_packages',    'Collect Packages'),
  ('vulnerability_scan',  'Vulnerability Scan'),
  ('collect_file_hashes', 'Scan File Hashes'),
  ('isolate_host',        'Isolate Host'),
  ('collect_users',       'Collect Users'),
  ('collect_auth_logs',   'Collect Auth Logs'),
];

class AgentsSection extends StatefulWidget {
  final DashboardApi api;
  const AgentsSection({super.key, required this.api});
  @override State<AgentsSection> createState() => _AgentsSectionState();
}

class _AgentsSectionState extends State<AgentsSection> {
  List<dynamic> _agents = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getAgents();
    if (!mounted) return;
    setState(() { _agents = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_agents.isEmpty) return const Center(child: Text('No agents', style: TextStyle(color: Colors.grey)));

    final online  = _agents.where((a) => (a['status'] ?? '') == 'online').length;

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(16, 12, 16, 4),
          child: Row(children: [
            Text('$online / ${_agents.length} online',
                style: const TextStyle(fontSize: 12, color: Colors.grey)),
            const Spacer(),
            Text('${_agents.length} total',
                style: const TextStyle(fontSize: 12, color: Colors.grey)),
          ]),
        ),
        Expanded(
          child: RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: _agents.length,
              itemBuilder: (_, i) {
                final a      = _agents[i] as Map<String, dynamic>;
                final online = (a['status'] ?? '') == 'online';
                final id     = a['id'] as int? ?? 0;
                return Card(
                  margin: const EdgeInsets.only(bottom: 6),
                  child: ListTile(
                    leading: Icon(Icons.computer, color: online ? Colors.green : Colors.grey),
                    title: Text((a['hostname'] ?? 'Agent $id').toString(),
                        style: const TextStyle(fontWeight: FontWeight.w600)),
                    subtitle: Text(
                      '${(a['os'] ?? a['platform'] ?? '').toString().toUpperCase()}'
                      '  ·  ${a['ip_address'] ?? '—'}'
                      '  ·  ${timeAgo(a['last_seen']?.toString())}',
                      style: const TextStyle(fontSize: 11),
                    ),
                    trailing: PopupMenuButton<String>(
                      onSelected: (task) async {
                        final ok = await widget.api.queueAgentTask(id, task);
                        if (context.mounted) {
                          ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                            content: Text(ok ? 'Task queued: $task' : 'Failed to queue task'),
                          ));
                        }
                      },
                      itemBuilder: (_) => _AGENT_TASKS
                          .map((t) => PopupMenuItem(value: t.$1, child: Text(t.$2)))
                          .toList(),
                    ),
                  ),
                );
              },
            ),
          ),
        ),
      ],
    );
  }
}

// ── MDM section ───────────────────────────────────────────────────────────────

const _MDM_CMDS = [
  ('collect_apps', 'Collect App Inventory'),
  ('sync',         'Force Sync'),
  ('lock',         'Lock Screen'),
  ('collect_logs', 'Collect Logs'),
];

class MDMSection extends StatefulWidget {
  final DashboardApi api;
  const MDMSection({super.key, required this.api});
  @override State<MDMSection> createState() => _MDMSectionState();
}

class _MDMSectionState extends State<MDMSection> {
  List<dynamic> _devices = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getMDMDevices();
    if (!mounted) return;
    setState(() { _devices = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_devices.isEmpty) {
      return Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: const [
            Icon(Icons.smartphone, size: 48, color: Colors.grey),
            SizedBox(height: 12),
            Text('No enrolled devices', style: TextStyle(color: Colors.grey)),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _devices.length,
        itemBuilder: (_, i) {
          final d   = _devices[i] as Map<String, dynamic>;
          final sta = (d['status'] ?? '').toString();
          final id  = d['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: Icon(Icons.smartphone, color: statusColor(sta)),
              title: Text((d['device_name'] ?? d['udid'] ?? 'Device $id').toString(),
                  style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text(
                '${d['model'] ?? ''}  ·  ${d['owner_email'] ?? '—'}'
                '\n${(d['compliance_status'] ?? 'unknown').toString().toUpperCase()}'
                '  ·  ${timeAgo(d['last_check_in']?.toString())}',
                style: const TextStyle(fontSize: 11),
              ),
              isThreeLine: true,
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  bool ok;
                  if (v == 'block') {
                    ok = await widget.api.blockMDMDevice(id);
                  } else if (v == 'unblock') {
                    ok = await widget.api.unblockMDMDevice(id);
                  } else {
                    ok = await widget.api.queueMDMCommand(id, v);
                  }
                  if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text(ok ? 'Done' : 'Action failed')));
                  }
                  if (ok) _load();
                },
                itemBuilder: (_) => [
                  ..._MDM_CMDS.map((c) => PopupMenuItem(value: c.$1, child: Text(c.$2))),
                  const PopupMenuDivider(),
                  if (sta == 'blocked')
                    const PopupMenuItem(value: 'unblock', child: Text('Unblock Device'))
                  else
                    const PopupMenuItem(
                      value: 'block',
                      child: Text('Block Device', style: TextStyle(color: Colors.red)),
                    ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Cases section ─────────────────────────────────────────────────────────────

class CasesSection extends StatefulWidget {
  final DashboardApi api;
  const CasesSection({super.key, required this.api});
  @override State<CasesSection> createState() => _CasesSectionState();
}

class _CasesSectionState extends State<CasesSection> {
  List<dynamic> _cases  = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getCases();
    if (!mounted) return;
    setState(() { _cases = r; _loading = false; });
  }

  void _showCreate() {
    final titleCtrl = TextEditingController();
    final descCtrl  = TextEditingController();
    String sev = 'medium';
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, ss) => Padding(
          padding: EdgeInsets.only(
              left: 16, right: 16, top: 16,
              bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              const Text('New Case', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
              const SizedBox(height: 12),
              TextField(controller: titleCtrl, decoration: const InputDecoration(labelText: 'Title', border: OutlineInputBorder())),
              const SizedBox(height: 10),
              TextField(controller: descCtrl, maxLines: 3, decoration: const InputDecoration(labelText: 'Description', border: OutlineInputBorder())),
              const SizedBox(height: 10),
              DropdownButtonFormField<String>(
                value: sev,
                decoration: const InputDecoration(labelText: 'Severity', border: OutlineInputBorder()),
                items: ['critical', 'high', 'medium', 'low'].map((s) =>
                    DropdownMenuItem(value: s, child: Text(s))).toList(),
                onChanged: (v) => ss(() => sev = v!),
              ),
              const SizedBox(height: 14),
              FilledButton(
                onPressed: () async {
                  Navigator.pop(ctx);
                  await widget.api.createCase(titleCtrl.text.trim(), descCtrl.text.trim(), sev);
                  _load();
                },
                child: const Text('Create'),
              ),
            ],
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 0),
          child: Row(
            mainAxisAlignment: MainAxisAlignment.end,
            children: [
              FilledButton.icon(
                onPressed: _showCreate,
                icon: const Icon(Icons.add, size: 16),
                label: const Text('New Case'),
              ),
            ],
          ),
        ),
        if (_cases.isEmpty)
          const Expanded(child: Center(child: Text('No cases', style: TextStyle(color: Colors.grey))))
        else
          Expanded(
            child: RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.all(8),
                itemCount: _cases.length,
                itemBuilder: (_, i) {
                  final c   = _cases[i] as Map<String, dynamic>;
                  final sta = (c['status'] ?? '').toString();
                  return Card(
                    margin: const EdgeInsets.only(bottom: 6),
                    child: ListTile(
                      leading: Icon(Icons.folder_special, color: statusColor(sta)),
                      title: Text((c['title'] ?? 'Case ${c['id']}').toString(),
                          maxLines: 1, overflow: TextOverflow.ellipsis,
                          style: const TextStyle(fontWeight: FontWeight.w600)),
                      subtitle: Text(
                          '${sta.toUpperCase()}  ·  ${(c['severity'] ?? '').toString().toUpperCase()}'
                          '  ·  ${timeAgo(c['created_at']?.toString())}',
                          style: const TextStyle(fontSize: 11)),
                      trailing: PopupMenuButton<String>(
                        onSelected: (v) async {
                          await widget.api.updateCaseStatus(c['id'] as int, v);
                          _load();
                        },
                        itemBuilder: (_) => const [
                          PopupMenuItem(value: 'in_progress', child: Text('In Progress')),
                          PopupMenuItem(value: 'closed',      child: Text('Close')),
                        ],
                      ),
                    ),
                  );
                },
              ),
            ),
          ),
      ],
    );
  }
}

// ── Approvals section ─────────────────────────────────────────────────────────

class ApprovalsSection extends StatefulWidget {
  final DashboardApi api;
  const ApprovalsSection({super.key, required this.api});
  @override State<ApprovalsSection> createState() => _ApprovalsSectionState();
}

class _ApprovalsSectionState extends State<ApprovalsSection> {
  List<dynamic> _tasks  = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getPendingApprovals();
    if (!mounted) return;
    setState(() { _tasks = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_tasks.isEmpty) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.check_circle, size: 48, color: Colors.green),
            SizedBox(height: 12),
            Text('No pending approvals', style: TextStyle(color: Colors.grey)),
          ],
        ),
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _tasks.length,
        itemBuilder: (_, i) {
          final t  = _tasks[i] as Map<String, dynamic>;
          final id = t['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text((t['task_type'] ?? 'Task').toString(),
                      style: const TextStyle(fontWeight: FontWeight.bold)),
                  const SizedBox(height: 4),
                  Text('Agent: ${t['agent_id'] ?? '—'}  ·  ${timeAgo(t['created_at']?.toString())}',
                      style: const TextStyle(fontSize: 12, color: Colors.grey)),
                  const SizedBox(height: 8),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          style: OutlinedButton.styleFrom(foregroundColor: Colors.red),
                          onPressed: () async {
                            await widget.api.rejectTask(id, 'Rejected from mobile admin');
                            _load();
                          },
                          child: const Text('Reject'),
                        ),
                      ),
                      const SizedBox(width: 10),
                      Expanded(
                        child: FilledButton(
                          onPressed: () async {
                            await widget.api.approveTask(id);
                            _load();
                          },
                          child: const Text('Approve'),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Firewall section ──────────────────────────────────────────────────────────

class FirewallSection extends StatefulWidget {
  final DashboardApi api;
  const FirewallSection({super.key, required this.api});
  @override State<FirewallSection> createState() => _FirewallSectionState();
}

class _FirewallSectionState extends State<FirewallSection> {
  List<dynamic> _rules  = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getFirewallRules();
    if (!mounted) return;
    setState(() { _rules = r; _loading = false; });
  }

  Color _actionColor(String a) {
    switch (a.toLowerCase()) {
      case 'allow': return Colors.green;
      case 'deny':
      case 'drop':
      case 'block': return Colors.red;
      default: return Colors.grey;
    }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_rules.isEmpty) return const Center(child: Text('No firewall rules', style: TextStyle(color: Colors.grey)));

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _rules.length,
        itemBuilder: (_, i) {
          final r   = _rules[i] as Map<String, dynamic>;
          final act = (r['action'] ?? '').toString();
          return Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: Icon(
                act.toLowerCase() == 'allow' ? Icons.check_circle_outline : Icons.block,
                color: _actionColor(act),
              ),
              title: Text(
                '${r['src_ip'] ?? 'any'}:${r['src_port'] ?? '*'} → '
                '${r['dst_ip'] ?? 'any'}:${r['dst_port'] ?? '*'}',
                style: const TextStyle(fontFamily: 'monospace', fontSize: 12),
              ),
              subtitle: Text(
                '${act.toUpperCase()}  ·  ${(r['protocol'] ?? 'any').toString().toUpperCase()}'
                '${r['description'] != null ? "  ·  ${r['description']}" : ""}',
                style: const TextStyle(fontSize: 11),
              ),
              trailing: IconButton(
                icon: const Icon(Icons.delete_outline, color: Colors.red),
                onPressed: () async {
                  final ok = await widget.api.deleteFirewallRule(r['id'] as int? ?? 0);
                  if (ok) _load();
                  else if (context.mounted) {
                    ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Delete failed')));
                  }
                },
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Playbooks section ─────────────────────────────────────────────────────────

class PlaybooksSection extends StatefulWidget {
  final DashboardApi api;
  const PlaybooksSection({super.key, required this.api});
  @override State<PlaybooksSection> createState() => _PlaybooksSectionState();
}

class _PlaybooksSectionState extends State<PlaybooksSection> {
  List<dynamic> _books  = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.getPlaybooks();
    if (!mounted) return;
    setState(() { _books = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    if (_books.isEmpty) return const Center(child: Text('No playbooks', style: TextStyle(color: Colors.grey)));

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _books.length,
        itemBuilder: (_, i) {
          final b       = _books[i] as Map<String, dynamic>;
          final enabled = b['is_enabled'] as bool? ?? b['enabled'] as bool? ?? false;
          return Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: Icon(
                Icons.play_circle_filled,
                color: enabled ? Colors.blue : Colors.grey,
              ),
              title: Text((b['name'] ?? 'Playbook ${b['id']}').toString(),
                  style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text(
                  '${enabled ? "ENABLED" : "DISABLED"}  ·  '
                  '${(b['trigger_type'] ?? '').toString()}',
                  style: const TextStyle(fontSize: 11)),
              trailing: Text(
                '${b['execution_count'] ?? 0} runs',
                style: const TextStyle(fontSize: 11, color: Colors.grey),
              ),
            ),
          );
        },
      ),
    );
  }
}
