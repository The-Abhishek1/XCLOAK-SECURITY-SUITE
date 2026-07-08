import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard — SOC Command Center
// ─────────────────────────────────────────────────────────────────────────────

class DashboardScreen extends StatefulWidget {
  final DashboardApi api;
  const DashboardScreen({super.key, required this.api});
  @override State<DashboardScreen> createState() => _DashboardState();
}

class _DashboardState extends State<DashboardScreen> {
  bool _loading = true;
  Map<String,dynamic> _ov  = {};
  Map<String,dynamic> _soc = {};
  List _critAlerts  = [];
  List _agents      = [];
  List _incidents   = [];
  DateTime? _lastRefreshed;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.overview().then((r)       { _ov       = r ?? {}; }),
      widget.api.socMetrics().then((r)      { _soc      = r ?? {}; }),
      widget.api.alerts(sev: 'critical', per: 5).then((r) { _critAlerts = r; }),
      widget.api.agents().then((r)          { _agents   = r; }),
      widget.api.incidents(per: 5).then((r) { _incidents = r; }),
    ]);
    _lastRefreshed = DateTime.now();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  int get _online => _agents.where((a) => str(a['status']) == 'online').length;

  int _riskScore() {
    final v = _ov['risk_score'];
    if (v is num) return v.toInt();
    return 0;
  }

  Color _riskColor([int? score]) {
    final s = score ?? _riskScore();
    if (s >= 75) return const Color(0xFFEF4444);
    if (s >= 50) return const Color(0xFFF97316);
    if (s >= 25) return const Color(0xFFF59E0B);
    return const Color(0xFF22C55E);
  }

  String _riskLabel([int? score]) {
    final s = score ?? _riskScore();
    if (s >= 75) return 'CRITICAL';
    if (s >= 50) return 'HIGH';
    if (s >= 25) return 'MEDIUM';
    return 'LOW';
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final cs    = Theme.of(context).colorScheme;
    final score = _riskScore();
    final col   = _riskColor(score);

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: EdgeInsets.zero,
        children: [

          // ── Gradient header ──────────────────────────────────────────
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topLeft, end: Alignment.bottomRight,
                colors: [col.withValues(alpha: .15), cs.surface],
              ),
            ),
            padding: const EdgeInsets.fromLTRB(16, 16, 16, 20),
            child: Row(children: [
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('RISK LEVEL', style: TextStyle(fontSize: 10, letterSpacing: 1.4,
                  color: cs.onSurface.withValues(alpha: .45), fontWeight: FontWeight.w700)),
                const SizedBox(height: 4),
                Row(children: [
                  Container(
                    width: 10, height: 10,
                    decoration: BoxDecoration(color: col, shape: BoxShape.circle),
                  ),
                  const SizedBox(width: 7),
                  Text(_riskLabel(score),
                    style: TextStyle(fontSize: 24, fontWeight: FontWeight.w900, color: col)),
                ]),
                const SizedBox(height: 6),
                Text(
                  _lastRefreshed != null
                    ? 'Updated ${_fmtTime(_lastRefreshed!)}'
                    : 'Tap to refresh',
                  style: TextStyle(fontSize: 11, color: cs.onSurface.withValues(alpha: .4)),
                ),
              ])),
              const SizedBox(width: 16),
              RingGauge(
                value: score / 100, color: col, size: 80,
                label: '$score', sublabel: '/ 100',
              ),
            ]),
          ),

          // ── KPI grid ────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 14, 12, 0),
            child: GridView.count(
              crossAxisCount: 3,
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              crossAxisSpacing: 8, mainAxisSpacing: 8,
              childAspectRatio: 1.05,
              children: [
                KpiCard(
                  label: 'Agents Online', icon: Icons.computer,
                  value: '$_online / ${_agents.length}',
                  color: _online > 0 ? const Color(0xFF22C55E) : Colors.grey),
                KpiCard(
                  label: 'Open Alerts', icon: Icons.notifications_active,
                  value: str(_ov['open_alerts'] ?? _ov['active_alerts'] ?? 0),
                  color: const Color(0xFFF97316)),
                KpiCard(
                  label: 'Critical', icon: Icons.crisis_alert,
                  value: str(_ov['critical_alerts'] ?? 0),
                  color: const Color(0xFFEF4444)),
                KpiCard(
                  label: 'Incidents', icon: Icons.bolt,
                  value: str(_ov['active_incidents'] ?? _ov['open_incidents'] ?? 0),
                  color: const Color(0xFF3B82F6)),
                KpiCard(
                  label: 'Open Cases', icon: Icons.folder_open,
                  value: str(_ov['open_cases'] ?? 0),
                  color: const Color(0xFF8B5CF6)),
                KpiCard(
                  label: 'Pending', icon: Icons.hourglass_top,
                  value: str(_ov['pending_approvals'] ?? 0),
                  color: const Color(0xFFF59E0B)),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // ── SOC metrics strip ────────────────────────────────────────
          if (_soc.isNotEmpty) ...[
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Row(children: [
                _SocMetric(label: 'MTTD', value: str(_soc['mttd'] ?? _soc['mean_time_to_detect'] ?? '—'), unit: 'min'),
                const SizedBox(width: 8),
                _SocMetric(label: 'MTTR', value: str(_soc['mttr'] ?? _soc['mean_time_to_respond'] ?? '—'), unit: 'min'),
                const SizedBox(width: 8),
                _SocMetric(label: 'Alerts/Day', value: str(_soc['alerts_today'] ?? _soc['alert_volume'] ?? '—'), unit: ''),
                const SizedBox(width: 8),
                _SocMetric(label: 'Resolved', value: str(_soc['resolved_today'] ?? '—'), unit: ''),
              ]),
            ),
            const SizedBox(height: 16),
          ],

          // ── Critical alerts preview ──────────────────────────────────
          if (_critAlerts.isNotEmpty)
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                SectionTitle('Critical Alerts',
                  trailing: TextButton(
                    onPressed: () {},
                    child: const Text('View All', style: TextStyle(fontSize: 12)))),
                ..._critAlerts.take(3).map((a) {
                  final alert = a as Map<String,dynamic>;
                  return _AlertPreview(alert: alert, api: widget.api, onAction: _load);
                }),
              ]),
            ),

          // ── Agent health grid ────────────────────────────────────────
          if (_agents.isNotEmpty)
            Padding(
              padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                SectionTitle('Agent Health',
                  trailing: Text('$_online / ${_agents.length} online',
                    style: TextStyle(fontSize: 11, color: Colors.grey.shade500))),
                Wrap(
                  spacing: 8, runSpacing: 8,
                  children: _agents.take(24).map((a) {
                    final online = str(a['status']) == 'online';
                    final name   = str(a['hostname'], 'Agent');
                    return Tooltip(
                      message: name,
                      child: Column(mainAxisSize: MainAxisSize.min, children: [
                        Container(
                          width: 34, height: 34,
                          decoration: BoxDecoration(
                            color: (online ? const Color(0xFF22C55E) : Colors.grey).withValues(alpha: .1),
                            borderRadius: BorderRadius.circular(8),
                            border: Border.all(
                              color: (online ? const Color(0xFF22C55E) : Colors.grey).withValues(alpha: .25))),
                          child: Icon(_osIcon(str(a['os'] ?? a['platform'])),
                            size: 16,
                            color: online ? const Color(0xFF22C55E) : Colors.grey.shade400),
                        ),
                        const SizedBox(height: 3),
                        Container(
                          width: 6, height: 6,
                          decoration: BoxDecoration(
                            color: online ? const Color(0xFF22C55E) : Colors.grey.shade400,
                            shape: BoxShape.circle)),
                      ]),
                    );
                  }).toList(),
                ),
                if (_agents.length > 24)
                  Padding(
                    padding: const EdgeInsets.only(top: 6),
                    child: Text('+${_agents.length - 24} more agents',
                      style: TextStyle(fontSize: 11, color: Colors.grey.shade500)),
                  ),
              ]),
            ),

          // ── Active incidents strip ───────────────────────────────────
          if (_incidents.isNotEmpty) ...[
            const SizedBox(height: 16),
            Padding(
              padding: const EdgeInsets.symmetric(horizontal: 12),
              child: SectionTitle('Active Incidents'),
            ),
            SizedBox(
              height: 104,
              child: ListView.builder(
                scrollDirection: Axis.horizontal,
                padding: const EdgeInsets.only(left: 12, right: 4),
                itemCount: _incidents.length,
                itemBuilder: (_, i) {
                  final inc = _incidents[i] as Map<String,dynamic>;
                  final col = sevColor(str(inc['severity']));
                  return Container(
                    width: 160,
                    margin: const EdgeInsets.only(right: 8),
                    padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
                    decoration: BoxDecoration(
                      color: col.withValues(alpha: .06),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: col.withValues(alpha: .25))),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Row(children: [
                        Icon(Icons.bolt, size: 12, color: col),
                        const SizedBox(width: 4),
                        SevChip(str(inc['severity'])),
                      ]),
                      const SizedBox(height: 5),
                      Text(str(inc['title'] ?? 'Incident'), maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
                      const Spacer(),
                      Text(timeAgo(inc['created_at']),
                        style: const TextStyle(fontSize: 10, color: Colors.grey)),
                    ]),
                  );
                },
              ),
            ),
          ],

          const SizedBox(height: 24),
        ],
      ),
    );
  }

  IconData _osIcon(String os) {
    if (os.contains('windows')) return Icons.laptop_windows;
    if (os.contains('mac') || os.contains('darwin')) return Icons.laptop_mac;
    if (os.contains('android')) return Icons.phone_android;
    if (os.contains('ios')) return Icons.phone_iphone;
    return Icons.computer;
  }

  String _fmtTime(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inSeconds < 60) return 'just now';
    return '${diff.inMinutes}m ago';
  }
}

class _SocMetric extends StatelessWidget {
  final String label, value, unit;
  const _SocMetric({required this.label, required this.value, required this.unit});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Expanded(child: Container(
      padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
      decoration: BoxDecoration(
        color: cs.surfaceContainerLow,
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: cs.outlineVariant)),
      child: Column(children: [
        Text(value + (unit.isNotEmpty ? ' $unit' : ''),
          style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w800),
          overflow: TextOverflow.ellipsis),
        const SizedBox(height: 2),
        Text(label, style: const TextStyle(fontSize: 9.5, color: Colors.grey),
          textAlign: TextAlign.center),
      ]),
    ));
  }
}

class _AlertPreview extends StatelessWidget {
  final Map<String,dynamic> alert;
  final DashboardApi api;
  final VoidCallback onAction;
  const _AlertPreview({required this.alert, required this.api, required this.onAction});

  @override
  Widget build(BuildContext context) {
    final id  = alert['id'] as int? ?? 0;
    final col = sevColor(str(alert['severity']));
    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: col.withValues(alpha: .3)),
        color: col.withValues(alpha: .04)),
      clipBehavior: Clip.hardEdge,
      child: Row(children: [
        Container(width: 4, color: col),
        Expanded(child: Padding(
          padding: const EdgeInsets.fromLTRB(10, 10, 6, 10),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(str(alert['rule_name'] ?? alert['message']),
              style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
              maxLines: 1, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 4),
            Row(children: [
              SevChip(str(alert['severity'])),
              const SizedBox(width: 6),
              Expanded(child: Text(
                '${str(alert['hostname'] ?? '')}  ·  ${timeAgo(alert['created_at'])}',
                style: const TextStyle(fontSize: 11, color: Colors.grey),
                overflow: TextOverflow.ellipsis)),
            ]),
          ]),
        )),
        Row(mainAxisSize: MainAxisSize.min, children: [
          _AlertAction(icon: Icons.check_circle_outline, color: const Color(0xFF22C55E), label: 'Ack',
            onTap: () async { await api.ackAlert(id); onAction(); }),
          _AlertAction(icon: Icons.close, color: Colors.grey, label: 'Resolve',
            onTap: () async { await api.resolveAlert(id); onAction(); }),
        ]),
      ]),
    );
  }
}

class _AlertAction extends StatelessWidget {
  final IconData icon; final Color color; final String label; final VoidCallback onTap;
  const _AlertAction({required this.icon, required this.color, required this.label, required this.onTap});

  @override
  Widget build(BuildContext context) => InkWell(
    onTap: onTap,
    borderRadius: BorderRadius.circular(6),
    child: Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 10),
      child: Icon(icon, size: 20, color: color),
    ),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Agents Screen — Enterprise endpoint management
// ─────────────────────────────────────────────────────────────────────────────

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
  List   _agents  = [];
  bool   _loading = true;
  String _filter  = 'all';
  String _query   = '';
  final _searchCtrl = TextEditingController();

  @override void initState() { super.initState(); _load(); }
  @override void dispose()   { _searchCtrl.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.agents();
    if (!mounted) return;
    setState(() { _agents = r; _loading = false; });
  }

  List get _visible {
    return _agents.where((a) {
      final map    = a as Map<String,dynamic>;
      final online = str(map['status']) == 'online';
      if (_filter == 'online'  && !online) return false;
      if (_filter == 'offline' && online)  return false;
      if (_query.isNotEmpty) {
        final q = _query.toLowerCase();
        return str(map['hostname']).toLowerCase().contains(q) ||
               str(map['ip_address']).toLowerCase().contains(q) ||
               str(map['os'] ?? map['platform']).toLowerCase().contains(q);
      }
      return true;
    }).toList();
  }

  int get _onlineCount => _agents.where((a) => str(a['status']) == 'online').length;

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final visible = _visible;

    return Column(children: [
      // Search bar
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
        child: TextField(
          controller: _searchCtrl,
          decoration: InputDecoration(
            hintText: 'Search by hostname, IP, OS…',
            hintStyle: const TextStyle(fontSize: 13),
            prefixIcon: const Icon(Icons.search, size: 19),
            suffixIcon: _query.isNotEmpty
              ? IconButton(icon: const Icon(Icons.close, size: 16),
                  onPressed: () { setState(() { _query = ''; _searchCtrl.clear(); }); })
              : null,
            isDense: true,
            contentPadding: const EdgeInsets.symmetric(vertical: 10),
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
          ),
          onChanged: (v) => setState(() => _query = v),
        ),
      ),
      // Filter row
      FilterRow(
        selected: _filter,
        onSelect: (v) => setState(() => _filter = v),
        chips: [
          ('All', 'all', _agents.length),
          ('Online', 'online', _onlineCount),
          ('Offline', 'offline', _agents.length - _onlineCount),
        ],
      ),
      // Summary row
      Padding(
        padding: const EdgeInsets.fromLTRB(16, 0, 16, 8),
        child: Row(children: [
          OnlineDot(true),
          const SizedBox(width: 6),
          Text('$_onlineCount / ${_agents.length} online',
            style: const TextStyle(fontSize: 12, color: Colors.grey)),
          const Spacer(),
          Text('${visible.length} shown',
            style: const TextStyle(fontSize: 12, color: Colors.grey)),
        ]),
      ),
      // Agent list
      Expanded(child: visible.isEmpty
        ? const XEmptyState('No agents match filter', icon: Icons.computer_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 80),
              itemCount: visible.length,
              itemBuilder: (_, i) => _AgentCard(
                agent: visible[i] as Map<String,dynamic>,
                api: widget.api,
                onAction: _load,
              ),
            ),
          )),
    ]);
  }
}

class _AgentCard extends StatelessWidget {
  final Map<String,dynamic> agent;
  final DashboardApi api;
  final VoidCallback onAction;
  const _AgentCard({required this.agent, required this.api, required this.onAction});

  bool get _online => str(agent['status']) == 'online';
  int  get _health => (agent['health_score'] ?? agent['risk_score'] ?? 85) is num
    ? (agent['health_score'] ?? agent['risk_score'] ?? 85).toInt() : 85;

  @override
  Widget build(BuildContext context) {
    final id  = agent['id'] as int? ?? 0;
    final os  = str(agent['os'] ?? agent['platform']).toLowerCase();
    final col = _online ? const Color(0xFF22C55E) : Colors.grey;

    return Card(
      margin: const EdgeInsets.only(bottom: 8),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Stack(clipBehavior: Clip.none, children: [
              Container(
                width: 42, height: 42,
                decoration: BoxDecoration(
                  color: col.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(11)),
                child: Icon(_osIcon(os), color: col, size: 22)),
              Positioned(right: -3, bottom: -3, child: OnlineDot(_online)),
            ]),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(agent['hostname'], 'Agent $id'),
                style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
              Text('${str(agent['ip_address'])}  ·  v${str(agent['version'])}',
                style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            ])),
            PopupMenuButton<String>(
              onSelected: (task) async {
                if (task == '__detail') { _showDetail(context, id, os); return; }
                final ok = await api.queueTask(id, task);
                if (context.mounted) xSnack(context, ok ? 'Task queued: $task' : 'Failed', error: !ok);
              },
              itemBuilder: (_) => [
                const PopupMenuItem(value: '__detail', child: Row(children: [
                  Icon(Icons.info_outline, size: 16), SizedBox(width: 8), Text('View Details')])),
                const PopupMenuDivider(),
                ..._kAgentTasks.map((t) => PopupMenuItem(value: t.$1, child: Text(t.$2))),
              ],
            ),
          ]),
          const SizedBox(height: 10),
          // Health bar
          HealthBar(_health),
          const SizedBox(height: 10),
          // Quick action row
          Row(children: [
            _QuickAction(label: 'Processes', icon: Icons.list_alt, onTap: () => api.queueTask(id, 'collect_processes').then((ok) { if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); })),
            const SizedBox(width: 6),
            _QuickAction(label: 'Packages', icon: Icons.inventory_2_outlined, onTap: () => api.queueTask(id, 'collect_packages').then((ok) { if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); })),
            const SizedBox(width: 6),
            _QuickAction(label: 'Vuln Scan', icon: Icons.bug_report_outlined, onTap: () => api.queueTask(id, 'vulnerability_scan').then((ok) { if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); })),
            const SizedBox(width: 6),
            _QuickAction(
              label: 'Isolate', icon: Icons.block, color: const Color(0xFFEF4444),
              onTap: () async {
                if (!context.mounted) return;
                if (await xConfirm(context, 'Isolate Host', 'This will block all network access for this agent.')) {
                  final ok = await api.queueTask(id, 'isolate_host');
                  if (context.mounted) xSnack(context, ok ? 'Isolation queued' : 'Failed', error: !ok);
                }
              },
            ),
          ]),
          const SizedBox(height: 6),
          Text('Last seen ${timeAgo(agent['last_seen'])}',
            style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
        ]),
      ),
    );
  }

  void _showDetail(BuildContext ctx, int id, String os) {
    showDetailSheet(ctx, str(agent['hostname'], 'Agent $id'), [
      ('ID',          str(id)),
      ('Status',      str(agent['status'])),
      ('OS',          str(agent['os'] ?? agent['platform'])),
      ('IP Address',  str(agent['ip_address'])),
      ('Version',     str(agent['version'])),
      ('Health',      '$_health / 100'),
      ('Last Seen',   timeAgo(agent['last_seen'])),
      ('Enrolled',    timeAgo(agent['created_at'])),
      ('Tenant ID',   str(agent['tenant_id'])),
    ], actions: [
      IconButton(
        icon: const Icon(Icons.more_vert),
        onPressed: () {},
      ),
    ]);
  }

  IconData _osIcon(String os) {
    if (os.contains('windows')) return Icons.laptop_windows;
    if (os.contains('mac') || os.contains('darwin')) return Icons.laptop_mac;
    if (os.contains('android')) return Icons.phone_android;
    if (os.contains('ios')) return Icons.phone_iphone;
    return Icons.computer;
  }
}

class _QuickAction extends StatelessWidget {
  final String label;
  final IconData icon;
  final Color? color;
  final VoidCallback onTap;
  const _QuickAction({required this.label, required this.icon, required this.onTap, this.color});

  @override
  Widget build(BuildContext context) {
    final c  = color ?? Theme.of(context).colorScheme.primary;
    return Expanded(child: GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 7),
        decoration: BoxDecoration(
          color: c.withValues(alpha: .07),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: c.withValues(alpha: .2))),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, size: 15, color: c),
          const SizedBox(height: 3),
          Text(label, style: TextStyle(fontSize: 9.5, color: c, fontWeight: FontWeight.w600),
            textAlign: TextAlign.center),
        ]),
      ),
    ));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Network Map
// ─────────────────────────────────────────────────────────────────────────────

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
    if (nodes.isEmpty) return const XEmptyState('No network data', icon: Icons.lan_outlined);
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Row(children: [
            KpiCard(label: 'Nodes', value: '${nodes.length}',
              color: const Color(0xFF3B82F6), icon: Icons.device_hub),
            const SizedBox(width: 8),
            KpiCard(label: 'Connections', value: '${edges.length}',
              color: const Color(0xFF22C55E), icon: Icons.cable),
          ]),
          const SizedBox(height: 16),
          SectionTitle('Network Nodes'),
          ...nodes.take(60).map((n) {
            final node = n as Map<String,dynamic>;
            final type = str(node['type'] ?? node['role']);
            final col  = _nodeColor(type);
            return Container(
              margin: const EdgeInsets.only(bottom: 6),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
              decoration: BoxDecoration(
                color: col.withValues(alpha: .04),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: col.withValues(alpha: .2))),
              child: Row(children: [
                Container(width: 36, height: 36,
                  decoration: BoxDecoration(
                    color: col.withValues(alpha: .1), borderRadius: BorderRadius.circular(9)),
                  child: Icon(_nodeIcon(type), color: col, size: 18)),
                const SizedBox(width: 12),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(str(node['label'] ?? node['ip'] ?? node['id']),
                    style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                  Text(type.isEmpty ? '—' : type,
                    style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
                ])),
                if (node['ip'] != null)
                  Text(str(node['ip']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ]),
            );
          }),
        ],
      ),
    );
  }

  Color _nodeColor(String type) {
    if (type.contains('server'))  return const Color(0xFF3B82F6);
    if (type.contains('router') || type.contains('gateway')) return const Color(0xFF8B5CF6);
    if (type.contains('agent') || type.contains('endpoint')) return const Color(0xFF22C55E);
    if (type.contains('internet') || type.contains('external')) return const Color(0xFFF97316);
    return Colors.grey;
  }

  IconData _nodeIcon(String type) {
    if (type.contains('server'))  return Icons.dns;
    if (type.contains('router') || type.contains('gateway')) return Icons.router;
    if (type.contains('agent') || type.contains('endpoint')) return Icons.computer;
    if (type.contains('internet') || type.contains('external')) return Icons.public;
    return Icons.device_hub;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Attack Paths
// ─────────────────────────────────────────────────────────────────────────────

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
    setState(() { _paths = (r?['paths'] as List?) ?? []; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_paths.isEmpty) return const XEmptyState('No attack paths detected', icon: Icons.route);
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          KpiCard(label: 'Paths Found', value: '${_paths.length}',
            color: const Color(0xFFEF4444), icon: Icons.route),
          const SizedBox(height: 16),
          SectionTitle('Attack Paths'),
          ..._paths.map((p) {
            final path = p as Map<String,dynamic>;
            final sev  = str(path['severity'] ?? path['risk']);
            final col  = sevColor(sev);
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: col.withValues(alpha: .25)),
                color: col.withValues(alpha: .04)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(child: Text(str(path['name'] ?? path['title'] ?? 'Attack Path'),
                    style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700))),
                  SevChip(sev),
                ]),
                if (path['description'] != null) ...[
                  const SizedBox(height: 6),
                  Text(str(path['description']),
                    style: const TextStyle(fontSize: 12, color: Colors.grey), maxLines: 2,
                    overflow: TextOverflow.ellipsis),
                ],
                const SizedBox(height: 8),
                Text('Discovered ${timeAgo(path['created_at'])}',
                  style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
              ]),
            );
          }),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Timeline
// ─────────────────────────────────────────────────────────────────────────────

class TimelineScreen extends StatefulWidget {
  final DashboardApi api;
  const TimelineScreen({super.key, required this.api});
  @override State<TimelineScreen> createState() => _TimelineState();
}

class _TimelineState extends State<TimelineScreen> {
  List   _events  = [];
  bool   _loading = true;
  String _filter  = '';

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _events = await widget.api.events(limit: 100);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  List get _filtered {
    if (_filter.isEmpty) return _events;
    return _events.where((e) {
      final t = (e['event_type'] ?? e['type'] ?? '').toString().toLowerCase();
      return t.contains(_filter);
    }).toList();
  }

  // Group events by date
  Map<String, List> _grouped() {
    final result = <String, List>{};
    for (final e in _filtered) {
      final ts = e['created_at'] ?? e['timestamp'] ?? '';
      String label;
      try {
        final dt   = DateTime.parse(ts.toString()).toLocal();
        final now  = DateTime.now();
        final diff = now.difference(dt);
        if (diff.inHours < 24)    label = 'Today';
        else if (diff.inHours < 48) label = 'Yesterday';
        else                        label = '${diff.inDays} days ago';
      } catch (_) { label = 'Unknown'; }
      result.putIfAbsent(label, () => []).add(e);
    }
    return result;
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final grouped = _grouped();
    return Column(children: [
      FilterRow(
        selected: _filter,
        onSelect: (v) => setState(() => _filter = v == _filter ? '' : v),
        chips: const [
          ('All', '', null), ('Alerts', 'alert', null),
          ('Check-ins', 'checkin', null), ('Tasks', 'task', null),
          ('Commands', 'command', null),
        ],
      ),
      Expanded(child: _events.isEmpty
        ? const XEmptyState('No events', icon: Icons.timeline)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView(
              padding: const EdgeInsets.fromLTRB(12, 4, 12, 20),
              children: grouped.entries.map((entry) => Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Padding(
                    padding: const EdgeInsets.only(top: 12, bottom: 8),
                    child: Text(entry.key, style: const TextStyle(
                      fontSize: 11, fontWeight: FontWeight.w800, color: Colors.grey, letterSpacing: .8)),
                  ),
                  ...entry.value.asMap().entries.map((ev) {
                    final e    = ev.value as Map<String,dynamic>;
                    final type = (e['event_type'] ?? e['type'] ?? 'event').toString();
                    final desc = (e['description'] ?? e['message'] ?? '').toString();
                    final ts   = (e['created_at'] ?? e['timestamp'] ?? '').toString();
                    final isLast = ev.key == entry.value.length - 1;
                    return TimelineEntry(
                      icon: _evIcon(type), color: _evColor(type),
                      title: _evLabel(type), subtitle: desc, time: timeAgo(ts), isLast: isLast,
                    );
                  }),
                ],
              )).toList(),
            ),
          )),
    ]);
  }

  IconData _evIcon(String t) => switch (t) {
    'checkin' || 'check_in' => Icons.sync,
    'alert'   || 'threat'   => Icons.warning_amber,
    'command' || 'task'     => Icons.terminal,
    'scan'                  => Icons.bug_report_outlined,
    'enrollment'            => Icons.phone_android,
    _                       => Icons.circle_outlined,
  };

  Color _evColor(String t) => switch (t) {
    'alert'  || 'threat'     => const Color(0xFFEF4444),
    'checkin'|| 'check_in'   => const Color(0xFF22C55E),
    'command'|| 'task'       => const Color(0xFF3B82F6),
    _                        => Colors.grey,
  };

  String _evLabel(String t) => switch (t) {
    'checkin' || 'check_in' => 'Check-in completed',
    'alert'                 => 'Alert generated',
    'threat'                => 'Threat detected',
    'command'               => 'Command received',
    'task'                  => 'Task executed',
    'scan'                  => 'Vulnerability scan',
    'enrollment'            => 'Device enrolled',
    _                       => t.replaceAll('_', ' '),
  };
}
