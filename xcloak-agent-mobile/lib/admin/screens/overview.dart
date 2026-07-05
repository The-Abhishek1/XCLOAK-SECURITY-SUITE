import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── Dashboard ─────────────────────────────────────────────────────────────────

class DashboardScreen extends StatefulWidget {
  final DashboardApi api;
  const DashboardScreen({super.key, required this.api});
  @override State<DashboardScreen> createState() => _DashboardState();
}

class _DashboardState extends State<DashboardScreen> {
  Map<String,dynamic>? _ov;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.overview();
    if (!mounted) return;
    setState(() { _ov = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final o = _ov ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          StatRow([
            ('Agents Online',    str(o['agents_online'] ?? o['online_agents'] ?? 0),     const Color(0xFF22C55E)),
            ('Open Alerts',      str(o['open_alerts']   ?? o['active_alerts'] ?? 0),     const Color(0xFFF97316)),
          ]),
          StatRow([
            ('Critical Alerts',  str(o['critical_alerts']   ?? 0),                        const Color(0xFFEF4444)),
            ('Open Incidents',   str(o['active_incidents']  ?? o['open_incidents'] ?? 0), const Color(0xFF3B82F6)),
          ]),
          StatRow([
            ('Open Cases',       str(o['open_cases']        ?? 0), const Color(0xFF8B5CF6)),
            ('Pending Approvals',str(o['pending_approvals'] ?? 0), const Color(0xFFF59E0B)),
          ]),
          if (o['risk_score'] != null) ...[
            const SizedBox(height: 12),
            Card(child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('RISK SCORE', style: TextStyle(fontSize: 11, letterSpacing: 1.2, color: Colors.grey)),
                const SizedBox(height: 8),
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(
                    value: (o['risk_score'] as num).toDouble() / 100,
                    backgroundColor: Colors.grey.shade200,
                    color: sevColor(_riskLabel(o['risk_score'] as num)),
                    minHeight: 8,
                  ),
                ),
                const SizedBox(height: 4),
                Text('${o['risk_score']} / 100 — ${_riskLabel(o['risk_score'] as num).toUpperCase()}',
                  style: const TextStyle(fontSize: 12)),
              ]),
            )),
          ],
        ],
      ),
    );
  }

  String _riskLabel(num v) {
    if (v >= 80) return 'critical';
    if (v >= 60) return 'high';
    if (v >= 40) return 'medium';
    return 'low';
  }
}

// ── Agents ────────────────────────────────────────────────────────────────────

const _kAgentTasks = [
  ('collect_processes',   'Collect Processes'),
  ('collect_connections', 'Collect Connections'),
  ('collect_packages',    'Collect Packages'),
  ('vulnerability_scan',  'Vulnerability Scan'),
  ('collect_file_hashes', 'Scan File Hashes'),
  ('isolate_host',        'Isolate Host'),
  ('collect_users',       'Collect Users'),
  ('collect_auth_logs',   'Collect Auth Logs'),
];

class AgentsScreen extends StatefulWidget {
  final DashboardApi api;
  const AgentsScreen({super.key, required this.api});
  @override State<AgentsScreen> createState() => _AgentsState();
}

class _AgentsState extends State<AgentsScreen> {
  List _agents = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.agents();
    if (!mounted) return;
    setState(() { _agents = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_agents.isEmpty) return const XEmptyState('No agents enrolled');
    final online = _agents.where((a) => str(a['status']) == 'online').length;
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(16,10,16,0),
        child: Row(children: [
          Text('$online / ${_agents.length} online', style: const TextStyle(fontSize: 12, color: Colors.grey)),
          const Spacer(),
          Text('${_agents.length} total', style: const TextStyle(fontSize: 12, color: Colors.grey)),
        ]),
      ),
      Expanded(child: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.all(8),
          itemCount: _agents.length,
          itemBuilder: (_, i) {
            final a      = _agents[i] as Map<String,dynamic>;
            final id     = a['id'] as int? ?? 0;
            final online = str(a['status']) == 'online';
            final os     = str(a['os'] ?? a['platform']).toLowerCase();
            final dotCol = online ? const Color(0xFF22C55E) : Colors.grey.shade400;
            return Card(
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                leading: Stack(
                  clipBehavior: Clip.none,
                  children: [
                    Container(
                      width: 40, height: 40,
                      decoration: BoxDecoration(
                        color: (online ? const Color(0xFF22C55E) : Colors.grey).withOpacity(.1),
                        borderRadius: BorderRadius.circular(10),
                      ),
                      child: Icon(_osIcon(os),
                          color: online ? const Color(0xFF22C55E) : Colors.grey, size: 20),
                    ),
                    Positioned(
                      right: -2, bottom: -2,
                      child: Container(
                        width: 11, height: 11,
                        decoration: BoxDecoration(
                          color: dotCol,
                          shape: BoxShape.circle,
                          border: Border.all(color: Theme.of(context).colorScheme.surface, width: 2),
                        ),
                      ),
                    ),
                  ],
                ),
                title: Text(str(a['hostname'], 'Agent $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
                subtitle: Text(
                  '${os.toUpperCase().isEmpty ? '—' : os.toUpperCase()}  ·  ${str(a['ip_address'])}'
                  '\nLast seen ${timeAgo(a['last_seen'])}',
                  style: const TextStyle(fontSize: 11),
                ),
                isThreeLine: true,
                trailing: PopupMenuButton<String>(
                  onSelected: (task) async {
                    if (task == '__detail') { _showDetail(a); return; }
                    final ok = await widget.api.queueTask(id, task);
                    if (context.mounted) xSnack(context, ok ? 'Task queued: $task' : 'Failed', error: !ok);
                  },
                  itemBuilder: (_) => [
                    const PopupMenuItem(value: '__detail', child: Text('View Details')),
                    const PopupMenuDivider(),
                    ..._kAgentTasks.map((t) => PopupMenuItem(value: t.$1, child: Text(t.$2))),
                  ],
                ),
              ),
            );
          },
        ),
      )),
    ]);
  }

  IconData _osIcon(String os) {
    if (os.contains('windows')) return Icons.laptop_windows;
    if (os.contains('mac') || os.contains('darwin')) return Icons.laptop_mac;
    if (os.contains('android')) return Icons.phone_android;
    if (os.contains('ios')) return Icons.phone_iphone;
    return Icons.computer;
  }

  void _showDetail(Map<String,dynamic> a) {
    showDetailSheet(context, str(a['hostname']), [
      ('ID',        str(a['id'])),
      ('OS',        str(a['os'] ?? a['platform'])),
      ('IP',        str(a['ip_address'])),
      ('Status',    str(a['status'])),
      ('Risk Score',str(a['risk_score'] ?? a['health_score'])),
      ('Last Seen', timeAgo(a['last_seen'])),
      ('Version',   str(a['version'])),
    ]);
  }
}

// ── Network Map ───────────────────────────────────────────────────────────────

class NetworkMapScreen extends StatefulWidget {
  final DashboardApi api;
  const NetworkMapScreen({super.key, required this.api});
  @override State<NetworkMapScreen> createState() => _NetworkMapState();
}

class _NetworkMapState extends State<NetworkMapScreen> {
  Map<String,dynamic>? _data;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.networkMap();
    if (!mounted) return;
    setState(() { _data = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final nodes = (_data?['nodes'] as List?) ?? [];
    final edges = (_data?['edges'] as List?) ?? [];
    if (nodes.isEmpty) return const XEmptyState('No network data');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(8),
        children: [
          StatRow([
            ('Nodes', '${nodes.length}', const Color(0xFF3B82F6)),
            ('Connections', '${edges.length}', const Color(0xFF22C55E)),
          ]),
          const SizedBox(height: 4),
          const Padding(
            padding: EdgeInsets.only(left: 4, bottom: 6),
            child: Text('NODES', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
          ),
          ...nodes.take(50).map((n) {
            final node = n as Map<String,dynamic>;
            return Card(
              margin: const EdgeInsets.only(bottom: 4),
              child: ListTile(
                dense: true,
                leading: Icon(Icons.circle, size: 10, color: statusColor(str(node['type']))),
                title: Text(str(node['label'] ?? node['ip'] ?? node['id']), style: const TextStyle(fontSize: 13)),
                subtitle: Text(str(node['type'] ?? node['role']), style: const TextStyle(fontSize: 11)),
              ),
            );
          }),
        ],
      ),
    );
  }
}

// ── Attack Paths ──────────────────────────────────────────────────────────────

class AttackPathsScreen extends StatefulWidget {
  final DashboardApi api;
  const AttackPathsScreen({super.key, required this.api});
  @override State<AttackPathsScreen> createState() => _AttackPathsState();
}

class _AttackPathsState extends State<AttackPathsScreen> {
  List _paths = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.attackPaths();
    if (!mounted) return;
    final paths = (r?['paths'] as List?) ?? [];
    setState(() { _paths = paths; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_paths.isEmpty) return const XEmptyState('No attack paths detected');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _paths.length,
        itemBuilder: (_, i) {
          final p = _paths[i] as Map<String,dynamic>;
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  SevChip(str(p['severity'] ?? p['risk'])),
                  const SizedBox(width: 8),
                  Expanded(child: Text(str(p['title'] ?? p['name']), style: const TextStyle(fontWeight: FontWeight.w600))),
                ]),
                if (p['steps'] is List) ...[
                  const SizedBox(height: 8),
                  ...((p['steps'] as List).asMap().entries.map((e) => Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Row(children: [
                      Text('${e.key + 1}. ', style: const TextStyle(color: Colors.grey, fontSize: 12)),
                      Expanded(child: Text(str(e.value is Map ? (e.value as Map)['label'] ?? e.value : e.value), style: const TextStyle(fontSize: 12))),
                    ]),
                  ))),
                ],
                const SizedBox(height: 4),
                Text(timeAgo(p['detected_at'] ?? p['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ]),
            ),
          );
        },
      ),
    );
  }
}

// ── Timeline ──────────────────────────────────────────────────────────────────

class TimelineScreen extends StatefulWidget {
  final DashboardApi api;
  const TimelineScreen({super.key, required this.api});
  @override State<TimelineScreen> createState() => _TimelineState();
}

class _TimelineState extends State<TimelineScreen> {
  List _events = [];
  bool _loading = true;
  int? _agentId;
  List _agents = [];

  @override void initState() { super.initState(); _init(); }

  Future<void> _init() async {
    final agents = await widget.api.agents();
    if (!mounted) return;
    setState(() => _agents = agents);
    if (agents.isNotEmpty) {
      _agentId = (agents.first as Map)['id'] as int?;
      await _load();
    } else {
      setState(() => _loading = false);
    }
  }

  Future<void> _load() async {
    if (_agentId == null) return;
    setState(() => _loading = true);
    final r = await widget.api.agentTimeline(_agentId!);
    if (!mounted) return;
    setState(() { _events = r; _loading = false; });
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
            items: _agents.map((a) {
              final m = a as Map<String,dynamic>;
              return DropdownMenuItem<int>(value: m['id'] as int?, child: Text(str(m['hostname']), style: const TextStyle(fontSize: 13)));
            }).toList(),
            onChanged: (v) { setState(() => _agentId = v); _load(); },
          ),
        ),
      if (_loading)
        const Expanded(child: Center(child: CircularProgressIndicator()))
      else if (_events.isEmpty)
        const Expanded(child: XEmptyState('No timeline events'))
      else
        Expanded(child: RefreshIndicator(
          onRefresh: _load,
          child: ListView.builder(
            padding: const EdgeInsets.all(8),
            itemCount: _events.length,
            itemBuilder: (_, i) {
              final e = _events[i] as Map<String,dynamic>;
              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Column(children: [
                    const SizedBox(height: 4),
                    Icon(Icons.circle, size: 8, color: sevColor(str(e['severity']))),
                    Container(width: 2, height: 48, color: Colors.grey.shade300),
                  ]),
                  const SizedBox(width: 8),
                  Expanded(child: Card(
                    margin: const EdgeInsets.only(bottom: 4),
                    child: Padding(
                      padding: const EdgeInsets.all(8),
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(str(e['event_type'] ?? e['type'] ?? e['action']), style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
                        Text(str(e['message'] ?? e['description']), style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 2, overflow: TextOverflow.ellipsis),
                        Text(timeAgo(e['timestamp'] ?? e['created_at']), style: const TextStyle(fontSize: 10, color: Colors.grey)),
                      ]),
                    ),
                  )),
                ],
              );
            },
          ),
        )),
    ]);
  }
}
