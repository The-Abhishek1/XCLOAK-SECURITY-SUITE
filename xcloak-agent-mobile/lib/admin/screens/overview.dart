import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Dashboard — SOC Command Center
// ─────────────────────────────────────────────────────────────────────────────

class DashboardScreen extends StatefulWidget {
  final DashboardApi api;
  final void Function(int)? onNavigate;
  const DashboardScreen({super.key, required this.api, this.onNavigate});
  @override State<DashboardScreen> createState() => _DashboardState();
}

class _DashboardState extends State<DashboardScreen> {
  bool _loading = true;
  Map<String,dynamic> _ov  = {};
  Map<String,dynamic> _soc = {};
  Map<String,dynamic> _risk = {};
  List _critAlerts  = [];
  List _agents      = [];
  List _incidents   = [];
  List _cases       = [];
  List _pending     = [];
  DateTime? _lastRefreshed;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.overview().then((r)       { _ov       = r ?? {}; }),
      widget.api.socMetrics().then((r)      { _soc      = r ?? {}; }),
      widget.api.riskPosture().then((r)     { _risk     = r ?? {}; }),
      widget.api.alerts(sev: 'critical', per: 5).then((r) { _critAlerts = r; }),
      widget.api.agents().then((r)          { _agents   = r; }),
      widget.api.incidents(per: 5).then((r) { _incidents = r; }),
      widget.api.cases().then((r)           { _cases    = r; }),
      widget.api.pendingApprovals().then((r) { _pending = r; }),
    ]);
    _lastRefreshed = DateTime.now();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  int get _online => _agents.where((a) => str(a['status']) == 'online').length;
  int get _openCases => _cases.where((c) => str((c as Map)['status']) != 'closed').length;

  // DashboardOverview has no risk_score field — the real composite score
  // lives on the Risk Posture snapshot (services.EnrichRiskPostureLiveData).
  int _riskScore() {
    final v = _risk['score'];
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
                  value: str(_ov['incidents'] ?? 0),
                  color: const Color(0xFF3B82F6)),
                KpiCard(
                  label: 'Open Cases', icon: Icons.folder_open,
                  value: '$_openCases',
                  color: const Color(0xFF8B5CF6)),
                KpiCard(
                  label: 'Pending', icon: Icons.hourglass_top,
                  value: '${_pending.length}',
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
                _SocMetric(label: 'MTTD', value: str(_soc['mttd_mins'], '—'), unit: 'min'),
                const SizedBox(width: 8),
                _SocMetric(label: 'MTTR', value: str(_soc['mttr_mins'], '—'), unit: 'min'),
                const SizedBox(width: 8),
                _SocMetric(label: 'Active Alerts', value: str(_soc['active_alerts'], '—'), unit: ''),
                const SizedBox(width: 8),
                _SocMetric(label: 'Open Cases', value: str(_soc['open_cases'], '—'), unit: ''),
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
                    onPressed: widget.onNavigate == null ? null : () => widget.onNavigate!(5),
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
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: () => _openDetail(context, id),
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
            const Icon(Icons.chevron_right, size: 18, color: Colors.grey),
            PopupMenuButton<String>(
              onSelected: (task) async {
                final ok = await api.queueTask(id, task);
                if (context.mounted) xSnack(context, ok ? 'Task queued: $task' : 'Failed', error: !ok);
              },
              itemBuilder: (_) => [
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
      ),
    );
  }

  void _openDetail(BuildContext ctx, int id) {
    Navigator.push(ctx, MaterialPageRoute(builder: (_) =>
      AgentDetailScreen(api: api, agentId: id, agent: agent)));
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
// Agent Detail — the web frontend's /agents/[id] has 19 tabs across 4 groups
// (Detection/Monitoring/Inventory/Response); scoped down here to the 6 real,
// already-built api.dart methods that had zero UI ever calling them
// (agentSummary/agentProcesses/agentConnections/agentPackages/agentVulns/
// agentTimeline) — previously the only "detail" view was a static 9-field
// sheet with no real collected data, and the agent list's only other
// interaction was dispatching tasks blind with no way to see the results.
// ─────────────────────────────────────────────────────────────────────────────

class AgentDetailScreen extends StatefulWidget {
  final DashboardApi api;
  final int agentId;
  final Map<String,dynamic> agent;
  const AgentDetailScreen({super.key, required this.api, required this.agentId, required this.agent});
  @override State<AgentDetailScreen> createState() => _AgentDetailState();
}

class _AgentDetailState extends State<AgentDetailScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  Map<String,dynamic>? _summary;
  List _processes = [], _connections = [], _packages = [], _vulns = [], _timeline = [];
  bool _loading = true;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 6, vsync: this);
    _load();
  }

  @override
  void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final results = await Future.wait([
      widget.api.agentSummary(widget.agentId),
      widget.api.agentProcesses(widget.agentId),
      widget.api.agentConnections(widget.agentId),
      widget.api.agentPackages(widget.agentId),
      widget.api.agentVulns(widget.agentId),
      widget.api.agentTimeline(widget.agentId),
    ]);
    if (!mounted) return;
    setState(() {
      _summary     = results[0] as Map<String,dynamic>?;
      _processes   = results[1] as List;
      _connections = results[2] as List;
      _packages    = results[3] as List;
      _vulns       = results[4] as List;
      _timeline    = results[5] as List;
      _loading     = false;
    });
  }

  Future<void> _dispatch(String taskType, {String? confirmTitle, String? confirmBody}) async {
    if (confirmTitle != null) {
      if (!await xConfirm(context, confirmTitle, confirmBody ?? '')) return;
    }
    final ok = await widget.api.queueTask(widget.agentId, taskType);
    if (!mounted) return;
    xSnack(context, ok ? 'Task queued: $taskType' : 'Failed to queue task', error: !ok);
  }

  @override
  Widget build(BuildContext context) {
    final hostname = str(widget.agent['hostname'], 'Agent ${widget.agentId}');
    return Scaffold(
      appBar: AppBar(
        title: Text(hostname, style: const TextStyle(fontSize: 16)),
        bottom: TabBar(
          controller: _tabs,
          isScrollable: true,
          tabs: [
            const Tab(text: 'Overview'),
            Tab(text: 'Processes (${_processes.length})'),
            Tab(text: 'Network (${_connections.length})'),
            Tab(text: 'Packages (${_packages.length})'),
            Tab(text: 'Vulns (${_vulns.length})'),
            const Tab(text: 'Timeline'),
          ],
        ),
      ),
      body: _loading ? xLoading() : TabBarView(
        controller: _tabs,
        children: [
          _overviewTab(),
          _processesTab(),
          _connectionsTab(),
          _packagesTab(),
          _vulnsTab(),
          _timelineTab(),
        ],
      ),
    );
  }

  Widget _overviewTab() {
    final a = widget.agent;
    return RefreshIndicator(onRefresh: _load, child: ListView(
      padding: const EdgeInsets.all(14),
      children: [
        Row(children: [
          // KpiCard's internal Row (icon + Spacer + trend chip) needs a
          // bounded width — placing it directly in a Row without Expanded
          // gives it unconstrained width and throws at layout time
          // ("BoxConstraints(unconstrained)"/"Null check operator used on a
          // null value"), which renders as a silently blank tab (no visible
          // error overlay for a layout exception that happens post-build).
          Expanded(child: KpiCard(label: 'Processes', value: str(_summary?['processes'], '${_processes.length}'),
            color: const Color(0xFF3B82F6), icon: Icons.list_alt,
            onTap: () => _tabs.animateTo(1))),
          const SizedBox(width: 8),
          Expanded(child: KpiCard(label: 'Connections', value: str(_summary?['connections'], '${_connections.length}'),
            color: const Color(0xFF22C55E), icon: Icons.cable,
            onTap: () => _tabs.animateTo(2))),
        ]),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(child: KpiCard(label: 'Packages', value: str(_summary?['packages'], '${_packages.length}'),
            color: const Color(0xFF8B5CF6), icon: Icons.inventory_2_outlined,
            onTap: () => _tabs.animateTo(3))),
          const SizedBox(width: 8),
          Expanded(child: KpiCard(label: 'Vulnerabilities', value: '${_vulns.length}',
            color: _vulns.isEmpty ? const Color(0xFF22C55E) : const Color(0xFFEF4444),
            icon: Icons.bug_report_outlined, onTap: () => _tabs.animateTo(4))),
        ]),
        const SizedBox(height: 16),
        SectionTitle('Agent Identity'),
        const SizedBox(height: 8),
        Container(
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: Theme.of(context).colorScheme.surfaceContainerLow,
            borderRadius: BorderRadius.circular(12)),
          child: Column(children: [
            _row('ID', str(widget.agentId)),
            _row('Status', str(a['status'])),
            _row('OS', str(a['os'] ?? a['platform'])),
            _row('IP Address', str(a['ip_address'])),
            _row('Version', str(a['version'])),
            _row('Last Seen', timeAgo(a['last_seen'])),
            _row('Enrolled', timeAgo(a['created_at'])),
            _row('Tenant ID', str(a['tenant_id'])),
          ]),
        ),
        const SizedBox(height: 16),
        SectionTitle('Actions'),
        const SizedBox(height: 8),
        Wrap(spacing: 8, runSpacing: 8, children: [
          for (final t in _kAgentTasks)
            OutlinedButton(
              onPressed: () => _dispatch(t.$1,
                confirmTitle: t.$1 == 'isolate_host' ? 'Isolate Host' : null,
                confirmBody: t.$1 == 'isolate_host'
                  ? 'This will block all network access for this agent.' : null),
              child: Text(t.$2, style: const TextStyle(fontSize: 12)),
            ),
        ]),
      ],
    ));
  }

  Widget _row(String label, String value) => Padding(
    padding: const EdgeInsets.symmetric(vertical: 4),
    child: Row(children: [
      SizedBox(width: 110, child: Text(label,
        style: TextStyle(fontSize: 12.5, color: Theme.of(context).colorScheme.onSurface.withValues(alpha: .55)))),
      Expanded(child: Text(value, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600))),
    ]),
  );

  Widget _processesTab() {
    if (_processes.isEmpty) return _emptyWithAction('No processes collected',
      Icons.list_alt, 'Collect Processes', () => _dispatch('collect_processes'));
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: _processes.length,
      itemBuilder: (_, i) {
        final p = _processes[i] as Map<String,dynamic>;
        return _tile(
          icon: Icons.memory,
          title: str(p['process_name'], 'unknown'),
          subtitle: 'PID ${str(p['pid'])} · PPID ${str(p['ppid'])} · ${str(p['username'])}',
          trailing: '${str(p['cpu_percent'], '0')}% CPU',
          detail: str(p['cmdline']),
        );
      },
    ));
  }

  Widget _connectionsTab() {
    if (_connections.isEmpty) return _emptyWithAction('No connections collected',
      Icons.cable, 'Collect Connections', () => _dispatch('collect_connections'));
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: _connections.length,
      itemBuilder: (_, i) {
        final c = _connections[i] as Map<String,dynamic>;
        return _tile(
          icon: Icons.swap_horiz,
          title: '${str(c['local_address'])} → ${str(c['remote_address'])}',
          subtitle: '${str(c['protocol']).toUpperCase()} · ${str(c['state'])}',
          trailing: str(c['process_name']),
        );
      },
    ));
  }

  Widget _packagesTab() {
    if (_packages.isEmpty) return _emptyWithAction('No packages collected',
      Icons.inventory_2_outlined, 'Collect Packages', () => _dispatch('collect_packages'));
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: _packages.length,
      itemBuilder: (_, i) {
        final p = _packages[i] as Map<String,dynamic>;
        return _tile(
          icon: Icons.inventory_2_outlined,
          title: str(p['package_name']),
          subtitle: 'v${str(p['version'])}',
        );
      },
    ));
  }

  Widget _vulnsTab() {
    if (_vulns.isEmpty) return _emptyWithAction('No vulnerabilities found',
      Icons.verified_user_outlined, 'Run Vulnerability Scan', () => _dispatch('vulnerability_scan'));
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: _vulns.length,
      itemBuilder: (_, i) {
        final v = _vulns[i] as Map<String,dynamic>;
        final sev = str(v['severity']).toLowerCase();
        final col = sev == 'critical' ? const Color(0xFFEF4444)
          : sev == 'high' ? const Color(0xFFF97316)
          : sev == 'medium' ? const Color(0xFFF59E0B) : const Color(0xFF3B82F6);
        return Container(
          margin: const EdgeInsets.only(bottom: 8),
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: col.withValues(alpha: .3)),
            color: col.withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(v['cve_id'], str(v['name'])),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              if ((v['is_kev'] ?? false) == true)
                Container(
                  margin: const EdgeInsets.only(right: 6),
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(color: const Color(0xFFEF4444).withValues(alpha: .15),
                    borderRadius: BorderRadius.circular(4)),
                  child: const Text('KEV', style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: Color(0xFFEF4444))),
                ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(color: col.withValues(alpha: .15), borderRadius: BorderRadius.circular(5)),
                child: Text(sev.toUpperCase(), style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: col)),
              ),
            ]),
            const SizedBox(height: 4),
            Text('${str(v['package_name'])} ${str(v['package_version'])} · CVSS ${str(v['cvss_score'])}',
              style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            if (str(v['description']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(v['description']), style: const TextStyle(fontSize: 11.5), maxLines: 3, overflow: TextOverflow.ellipsis),
            ],
          ]),
        );
      },
    ));
  }

  Widget _timelineTab() {
    if (_timeline.isEmpty) return const XEmptyState('No timeline events', icon: Icons.history);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12),
      itemCount: _timeline.length,
      itemBuilder: (_, i) {
        final e = _timeline[i] as Map<String,dynamic>;
        final type = str(e['event_type']);
        return _tile(
          icon: type.contains('alert') ? Icons.warning_amber_rounded
            : type.contains('incident') ? Icons.report_problem_outlined
            : type.contains('process') ? Icons.memory
            : Icons.circle_outlined,
          title: str(e['message'], type),
          subtitle: '${type.replaceAll('_', ' ')} · ${str(e['source'])}',
          trailing: timeAgo(e['created_at']),
        );
      },
    ));
  }

  Widget _tile({required IconData icon, required String title, String? subtitle, String? trailing, String? detail}) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceContainerLow,
        borderRadius: BorderRadius.circular(10)),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Icon(icon, size: 16, color: Theme.of(context).colorScheme.onSurface.withValues(alpha: .5)),
        const SizedBox(width: 10),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600),
            maxLines: 1, overflow: TextOverflow.ellipsis),
          if (subtitle != null && subtitle.isNotEmpty)
            Text(subtitle, style: const TextStyle(fontSize: 11, color: Colors.grey),
              maxLines: 1, overflow: TextOverflow.ellipsis),
          if (detail != null && detail.isNotEmpty)
            Text(detail, style: const TextStyle(fontSize: 10.5, color: Colors.grey, fontFamily: 'monospace'),
              maxLines: 1, overflow: TextOverflow.ellipsis),
        ])),
        if (trailing != null)
          Padding(
            padding: const EdgeInsets.only(left: 8),
            child: Text(trailing, style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
          ),
      ]),
    );
  }

  Widget _emptyWithAction(String message, IconData icon, String actionLabel, VoidCallback onTap) {
    return Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, size: 56, color: Colors.grey.withValues(alpha: .4)),
      const SizedBox(height: 12),
      Text(message, style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w600)),
      const SizedBox(height: 12),
      OutlinedButton.icon(onPressed: () { onTap(); _load(); },
        icon: const Icon(Icons.play_arrow, size: 16), label: Text(actionLabel)),
    ]));
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
            Expanded(child: KpiCard(label: 'Nodes', value: '${nodes.length}',
              color: const Color(0xFF3B82F6), icon: Icons.device_hub)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Connections', value: '${edges.length}',
              color: const Color(0xFF22C55E), icon: Icons.cable)),
          ]),
          const SizedBox(height: 16),
          SectionTitle('Network Nodes'),
          ...nodes.take(60).map((n) {
            final node = n as Map<String,dynamic>;
            final type = str(node['type'] ?? node['role']);
            final col  = _nodeColor(type);
            return InkWell(
              onTap: () => _showNodeActions(node),
              borderRadius: BorderRadius.circular(10),
              child: Container(
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
                  Text(str(node['hostname'] ?? node['ip'] ?? node['id']),
                    style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                  Text(type.isEmpty ? '—' : type,
                    style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
                ])),
                if (node['ip'] != null)
                  Text(str(node['ip']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ]),
              ),
            );
          }),
        ],
      ),
    );
  }

  void _showNodeActions(Map<String,dynamic> node) {
    final agentId = node['agent_id'] as int?;
    final ip      = str(node['ip'], '');
    showModalBottomSheet(
      context: context,
      builder: (ctx) => SafeArea(child: Column(mainAxisSize: MainAxisSize.min, children: [
        sheetHeader(str(node['hostname'] ?? node['ip'] ?? node['id'], 'Node')),
        if (agentId != null && agentId > 0) ...[
          ListTile(leading: const Icon(Icons.list_alt), title: const Text('Collect Processes'),
            onTap: () async { Navigator.pop(ctx); final ok = await widget.api.queueTask(agentId, 'collect_processes'); if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); }),
          ListTile(leading: const Icon(Icons.bug_report_outlined), title: const Text('Vulnerability Scan'),
            onTap: () async { Navigator.pop(ctx); final ok = await widget.api.queueTask(agentId, 'vulnerability_scan'); if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); }),
          ListTile(leading: const Icon(Icons.article_outlined), title: const Text('Collect Auth Logs'),
            onTap: () async { Navigator.pop(ctx); final ok = await widget.api.queueTask(agentId, 'collect_auth_logs'); if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); }),
          ListTile(leading: const Icon(Icons.block, color: Color(0xFFEF4444)), title: const Text('Isolate Endpoint'),
            onTap: () async {
              Navigator.pop(ctx);
              if (!context.mounted) return;
              if (await xConfirm(context, 'Isolate Host', 'This will block all network access for this agent.')) {
                final ok = await widget.api.queueTask(agentId, 'isolate_host');
                if (context.mounted) xSnack(context, ok ? 'Isolation queued' : 'Failed', error: !ok);
              }
            }),
        ],
        if (ip.isNotEmpty)
          ListTile(leading: const Icon(Icons.flag_outlined), title: const Text('Add IP to IOCs'),
            onTap: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createIoc({'type': 'ip', 'indicator': ip, 'severity': 'high', 'description': 'From network map'});
              if (context.mounted) xSnack(context, ok ? 'IOC created' : 'Failed', error: !ok);
            }),
      ])),
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
  Map<String,Map<String,dynamic>> _nodesById = {};
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.attackPaths();
    if (!mounted) return;
    // AttackPathGraph wraps ranked paths under `top_paths`, not `paths`.
    final nodes = (r?['nodes'] as List?) ?? [];
    setState(() {
      _paths = (r?['top_paths'] as List?) ?? [];
      _nodesById = {for (final n in nodes) str((n as Map)['id']): n as Map<String,dynamic>};
      _loading = false;
    });
  }

  void _showPathActions(Map<String,dynamic> path) {
    final hops = (path['hops'] as List?)?.map(str).toList() ?? [];
    final target = hops.isEmpty ? null : _nodesById[hops.last];
    final agentId = target?['agent_id'] as int?;
    showModalBottomSheet(
      context: context,
      builder: (ctx) => SafeArea(child: Column(mainAxisSize: MainAxisSize.min, children: [
        sheetHeader(str(path['target_hostname'], 'Target')),
        if (agentId != null && agentId > 0) ...[
          ListTile(leading: const Icon(Icons.bug_report_outlined), title: const Text('Vulnerability Scan'),
            onTap: () async { Navigator.pop(ctx); final ok = await widget.api.queueTask(agentId, 'vulnerability_scan'); if (context.mounted) xSnack(context, ok ? 'Queued' : 'Failed', error: !ok); }),
          ListTile(leading: const Icon(Icons.block, color: Color(0xFFEF4444)), title: const Text('Isolate Endpoint'),
            onTap: () async {
              Navigator.pop(ctx);
              if (!context.mounted) return;
              if (await xConfirm(context, 'Isolate Host', 'This will block all network access for this agent.')) {
                final ok = await widget.api.queueTask(agentId, 'isolate_host');
                if (context.mounted) xSnack(context, ok ? 'Isolation queued' : 'Failed', error: !ok);
              }
            }),
        ] else
          const ListTile(leading: Icon(Icons.info_outline), title: Text('No agent linked to this target')),
      ])),
    );
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
            // RankedAttackPath — target_risk_level ("critical"/"high"/...),
            // score (higher = more exploitable), hops (internet -> ... -> target).
            final path = p as Map<String,dynamic>;
            final sev  = str(path['target_risk_level']);
            final col  = sevColor(sev);
            final hops = (path['hops'] as List?)?.map(str).toList() ?? [];
            final phases = (path['kill_chain_phases'] as List?)?.map(str).toList() ?? [];
            return InkWell(
              onTap: () => _showPathActions(path),
              borderRadius: BorderRadius.circular(12),
              child: Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: col.withValues(alpha: .25)),
                color: col.withValues(alpha: .04)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(child: Text(str(path['target_hostname'], 'Attack Path'),
                    style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700))),
                  SevChip(sev),
                ]),
                const SizedBox(height: 6),
                Text(
                  hops.isEmpty ? '—' : hops.join('  →  '),
                  style: const TextStyle(fontSize: 12, color: Colors.grey), maxLines: 2,
                  overflow: TextOverflow.ellipsis),
                const SizedBox(height: 8),
                Row(children: [
                  if (str(path['path_type'], '').isNotEmpty) ...[
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: col.withValues(alpha: .12), borderRadius: BorderRadius.circular(6)),
                      child: Text(str(path['path_type']),
                        style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700, color: col))),
                    const SizedBox(width: 8),
                  ],
                  Text('Score ${str(path['score'], '0')}',
                    style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                  if (phases.isNotEmpty) ...[
                    const SizedBox(width: 8),
                    Expanded(child: Text(phases.join(', '),
                      style: const TextStyle(fontSize: 10.5, color: Colors.grey),
                      maxLines: 1, overflow: TextOverflow.ellipsis)),
                  ],
                ]),
              ]),
              ),
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

// ─────────────────────────────────────────────────────────────────────────────
// Deploy Agent — 4-step onboarding wizard (mirrors web /agents/onwards)
// ─────────────────────────────────────────────────────────────────────────────

const _kDeploySteps = [
  (1, Icons.vpn_key,       'Generate'),
  (2, Icons.description,   'Configure'),
  (3, Icons.play_arrow,    'Run'),
  (4, Icons.verified_user, 'Verify'),
];

class DeployAgentScreen extends StatefulWidget {
  final DashboardApi api;
  const DeployAgentScreen({super.key, required this.api});
  @override State<DeployAgentScreen> createState() => _DeployAgentState();
}

class _DeployAgentState extends State<DeployAgentScreen> {
  int    _step       = 1;
  String _token      = '';
  bool   _generating = false;
  bool   _checking   = false;
  bool   _found      = false;
  final _labelCtrl = TextEditingController();
  late final TextEditingController _urlCtrl;

  @override
  void initState() {
    super.initState();
    _urlCtrl = TextEditingController(text: widget.api.c.baseUrl);
  }

  @override
  void dispose() { _labelCtrl.dispose(); _urlCtrl.dispose(); super.dispose(); }

  Future<void> _generate() async {
    setState(() => _generating = true);
    final r = await widget.api.generateInstallToken(_labelCtrl.text.trim());
    if (!mounted) return;
    setState(() => _generating = false);
    if (r == null || r['error'] != null || str(r['token'], '').isEmpty) {
      xSnack(context,
        r != null && r['error'] != null
          ? str(r['error'])
          : 'Failed to generate token — ensure you are logged in as admin.',
        error: true);
      return;
    }
    setState(() { _token = str(r['token']); _step = 2; });
  }

  Future<void> _checkForAgent() async {
    setState(() => _checking = true);
    final agents = await widget.api.agents();
    if (!mounted) return;
    // Only count an agent whose enrollment happened in the last 2 minutes —
    // matching the web wizard's fix for the same false-positive: this demo
    // tenant already has agents from before this onboarding session, so a
    // bare "agents.isNotEmpty" check would report success on the first click
    // regardless of whether *this* token was ever actually used.
    final recent = agents.any((a) {
      final map = a as Map<String,dynamic>;
      final raw = map['created_at'] ?? map['last_seen'];
      if (raw == null) return false;
      try {
        final created = DateTime.parse(raw.toString());
        return DateTime.now().difference(created).inMinutes < 2;
      } catch (_) { return false; }
    });
    setState(() { _checking = false; if (recent) _found = true; });
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(16),
      children: [
        // Step indicator
        Row(children: [
          for (final s in _kDeploySteps)
            Expanded(child: Column(children: [
              Container(
                width: 32, height: 32,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: _step > s.$1
                    ? const Color(0xFF22C55E)
                    : (_step == s.$1 ? cs.primary.withValues(alpha: .15) : cs.surfaceContainerLow),
                  border: Border.all(
                    color: _step > s.$1
                      ? const Color(0xFF22C55E)
                      : (_step == s.$1 ? cs.primary : cs.outlineVariant),
                    width: 2)),
                child: Icon(_step > s.$1 ? Icons.check : s.$2, size: 16,
                  color: _step > s.$1 ? Colors.white : (_step == s.$1 ? cs.primary : cs.onSurfaceVariant)),
              ),
              const SizedBox(height: 4),
              Text(s.$3, style: TextStyle(fontSize: 9.5,
                fontWeight: FontWeight.w600,
                color: _step == s.$1 ? cs.primary : (_step > s.$1 ? const Color(0xFF22C55E) : cs.onSurfaceVariant))),
            ])),
        ]),
        const SizedBox(height: 20),

        if (_step == 1) _buildStep1(cs),
        if (_step == 2) _buildStep2(cs),
        if (_step == 3) _buildStep3(cs),
        if (_step == 4) _buildStep4(cs),
      ],
    );
  }

  Widget _buildStep1(ColorScheme cs) => Card(
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Generate an install token', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
        const SizedBox(height: 4),
        Text(
          'A one-time token that lets the agent register securely. Expires in 24 hours and can only be used once.',
          style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant)),
        const SizedBox(height: 14),
        xField(_labelCtrl, 'Agent label (e.g. prod-web-01)'),
        const SizedBox(height: 10),
        xField(_urlCtrl, 'XCloak server URL'),
        const SizedBox(height: 14),
        SizedBox(width: double.infinity, child: FilledButton.icon(
          onPressed: _generating ? null : _generate,
          icon: _generating
            ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.vpn_key, size: 16),
          label: Text(_generating ? 'Generating…' : 'Generate Install Token'),
        )),
      ]),
    ),
  );

  Widget _buildStep2(ColorScheme cs) => Card(
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Configure the agent', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
        const SizedBox(height: 4),
        Text(
          'Create a .env file in the agent directory with these values. The agent reads this file automatically on startup.',
          style: TextStyle(fontSize: 12, color: cs.onSurfaceVariant)),
        const SizedBox(height: 14),
        Container(
          padding: const EdgeInsets.all(10),
          decoration: BoxDecoration(
            color: cs.primary.withValues(alpha: .08),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: cs.primary.withValues(alpha: .25))),
          child: Row(children: [
            Expanded(child: Text(_token,
              style: const TextStyle(fontSize: 11, fontFamily: 'monospace'))),
            IconButton(
              icon: const Icon(Icons.copy, size: 16),
              padding: EdgeInsets.zero, constraints: const BoxConstraints(),
              onPressed: () => copyToClipboard(context, _token)),
          ]),
        ),
        const SizedBox(height: 12),
        Text('1. Create xcloak-agent-desktop/.env',
          style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: cs.onSurfaceVariant)),
        const SizedBox(height: 6),
        _codeBlock('XCLOAK_INSTALL_TOKEN=$_token\nXCLOAK_SERVER_URL=${_urlCtrl.text}'),
        const SizedBox(height: 14),
        Row(children: [
          Expanded(child: OutlinedButton(onPressed: () => setState(() => _step = 1), child: const Text('Back'))),
          const SizedBox(width: 10),
          Expanded(child: FilledButton(onPressed: () => setState(() => _step = 3), child: const Text('Next'))),
        ]),
      ]),
    ),
  );

  Widget _buildStep3(ColorScheme cs) => Card(
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Build and run the agent', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
        const SizedBox(height: 14),
        Text('1. Build from source',
          style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: cs.onSurfaceVariant)),
        const SizedBox(height: 6),
        _codeBlock('cd xcloak-agent-desktop\ngo build -o xcloak-agent-desktop ./main.go'),
        const SizedBox(height: 12),
        Text('2. Run (first time — reads token from .env and registers)',
          style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: cs.onSurfaceVariant)),
        const SizedBox(height: 6),
        _codeBlock('./xcloak-agent-desktop'),
        const SizedBox(height: 12),
        Text('On every restart after this, it loads the saved token automatically.',
          style: TextStyle(fontSize: 11, color: cs.onSurfaceVariant)),
        const SizedBox(height: 14),
        Row(children: [
          Expanded(child: OutlinedButton(onPressed: () => setState(() => _step = 2), child: const Text('Back'))),
          const SizedBox(width: 10),
          Expanded(child: FilledButton(onPressed: () => setState(() => _step = 4), child: const Text('Next'))),
        ]),
      ]),
    ),
  );

  Widget _buildStep4(ColorScheme cs) => Card(
    child: Padding(
      padding: const EdgeInsets.all(16),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Text('Verify the agent is connected', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
        const SizedBox(height: 14),
        Container(
          width: double.infinity,
          padding: const EdgeInsets.all(20),
          decoration: BoxDecoration(
            color: (_found ? const Color(0xFF22C55E) : cs.primary).withValues(alpha: .08),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: (_found ? const Color(0xFF22C55E) : cs.primary).withValues(alpha: .3))),
          child: Column(children: [
            Icon(_found ? Icons.check_circle : Icons.terminal, size: 36,
              color: _found ? const Color(0xFF22C55E) : cs.primary),
            const SizedBox(height: 8),
            Text(_found ? 'Agent detected!' : 'Waiting for agent…',
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w700,
                color: _found ? const Color(0xFF22C55E) : null)),
            const SizedBox(height: 4),
            Text(
              _found
                ? 'Your agent is registered and running.'
                : 'Run the agent on the target machine. It will appear here within 30 seconds.',
              textAlign: TextAlign.center,
              style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
          ]),
        ),
        const SizedBox(height: 14),
        SizedBox(width: double.infinity, child: OutlinedButton.icon(
          onPressed: _checking ? null : _checkForAgent,
          icon: _checking
            ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
            : const Icon(Icons.refresh, size: 16),
          label: Text(_checking ? 'Checking…' : 'Check Now'),
        )),
        const SizedBox(height: 16),
        Text('What this agent will collect every 30s:',
          style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: cs.onSurfaceVariant)),
        const SizedBox(height: 6),
        ...const [
          'Processes — running process list with PIDs',
          'Connections — active network connections + remote IPs',
          'Packages — installed packages and versions (for CVE scanning)',
          'Users — local user accounts and shells',
          'Auth logs — login attempts, sudo usage',
          'File hashes — SHA256/MD5 of watched files (FIM)',
        ].map((line) => Padding(
          padding: const EdgeInsets.only(bottom: 4),
          child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Icon(Icons.check, size: 13, color: Color(0xFF22C55E)),
            const SizedBox(width: 6),
            Expanded(child: Text(line, style: const TextStyle(fontSize: 11.5))),
          ]),
        )),
      ]),
    ),
  );

  Widget _codeBlock(String code) => Container(
    width: double.infinity,
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(
      color: Colors.black.withValues(alpha: .85),
      borderRadius: BorderRadius.circular(8)),
    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Expanded(child: Text(code,
        style: const TextStyle(fontSize: 10.5, fontFamily: 'monospace', color: Colors.greenAccent))),
      IconButton(
        icon: const Icon(Icons.copy, size: 14, color: Colors.white70),
        padding: EdgeInsets.zero, constraints: const BoxConstraints(),
        onPressed: () => copyToClipboard(context, code)),
    ]),
  );
}
