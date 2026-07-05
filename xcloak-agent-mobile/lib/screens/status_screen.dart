import 'package:flutter/material.dart';
import 'package:flutter_background_service/flutter_background_service.dart';

import '../admin/api.dart';
import '../admin/shell.dart';
import '../services/enrollment_service.dart';
import '../services/posture_collector.dart';
import '../services/secure_storage.dart';
import '../services/threat_detector.dart';
import 'setup_screen.dart';

class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key});

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs;

  // ── Agent / posture state ─────────────────────────────────────────────────
  bool _serviceRunning = false;
  bool _rooted         = false;
  bool _devMode        = false;
  List<String> _sideloaded = [];
  String _osVersion    = '';
  String? _deviceId;

  // ── Dashboard state ───────────────────────────────────────────────────────
  DashboardApi? _dash;
  Map<String, dynamic>? _overview;
  List<dynamic> _alerts    = [];
  List<dynamic> _agents    = [];
  List<dynamic> _incidents = [];
  bool _dashAvailable = false;
  bool _dashLoading   = false;

  String _alertFilter = '';

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 3, vsync: this);
    _tabs.addListener(() {
      if (!_tabs.indexIsChanging) _onTabChanged(_tabs.index);
    });
    _refreshAgent();
    _initDashboard();
  }

  @override
  void dispose() {
    _tabs.dispose();
    super.dispose();
  }

  Future<void> _refreshAgent() async {
    final posture    = await PostureCollector.collect();
    final sideloaded = await ThreatDetector.sideloadedPackages();
    final deviceId   = await SecureStore.deviceId();
    final running    = await FlutterBackgroundService().isRunning();
    if (!mounted) return;
    setState(() {
      _serviceRunning = running;
      _rooted         = posture.isRooted;
      _devMode        = posture.developerModeOn;
      _osVersion      = posture.osVersion;
      _sideloaded     = sideloaded;
      _deviceId       = deviceId?.toString();
    });
  }

  Future<void> _initDashboard() async {
    final dash = await DashboardApi.create();
    setState(() { _dash = dash; _dashAvailable = dash != null; });
    if (dash != null) _loadDashboard();
  }

  Future<void> _loadDashboard() async {
    if (_dash == null) return;
    setState(() => _dashLoading = true);
    final results = await Future.wait([
      _dash!.overview(),
      _dash!.alerts(sev: _alertFilter),
      _dash!.agents(),
      _dash!.incidents(),
    ]);
    if (!mounted) return;
    setState(() {
      _overview  = results[0] as Map<String, dynamic>?;
      _alerts    = results[1] as List<dynamic>;
      _agents    = results[2] as List<dynamic>;
      _incidents = results[3] as List<dynamic>;
      if (_overview != null && _overview!['active_incidents'] == null) {
        _overview = {..._overview!, 'active_incidents': _incidents.length};
      }
      _dashLoading = false;
    });
  }

  void _onTabChanged(int i) {
    if (i > 0 && _dashAvailable && _alerts.isEmpty && _agents.isEmpty) {
      _loadDashboard();
    }
  }

  Future<void> _toggleService() async {
    final service = FlutterBackgroundService();
    if (_serviceRunning) {
      service.invoke('stop');
    } else {
      await service.startService();
    }
    await Future.delayed(const Duration(milliseconds: 500));
    await _refreshAgent();
  }

  Future<void> _unenroll() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Unenroll Device'),
        content: const Text(
            'This will remove the agent token and stop monitoring. Continue?'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(context, false),
              child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Unenroll',
                style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await EnrollmentService.unenroll();
    if (!mounted) return;
    Navigator.pushReplacement(
        context, MaterialPageRoute(builder: (_) => const SetupScreen()));
  }

  Future<void> _enterAdminMode() async {
    final keyCtrl = TextEditingController();
    final result = await showDialog<String>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Admin API Key'),
        content: TextField(
          controller: keyCtrl,
          decoration: const InputDecoration(
            labelText: 'API Key',
            hintText: 'xck_…',
            helperText: 'Create one in Settings → API Keys on the dashboard.',
            prefixIcon: Icon(Icons.vpn_key),
          ),
          obscureText: true,
          autocorrect: false,
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Cancel'),
          ),
          FilledButton(
            onPressed: () => Navigator.pop(context, keyCtrl.text.trim()),
            child: const Text('Connect'),
          ),
        ],
      ),
    );
    if (result == null || result.isEmpty) return;
    await SecureStore.saveApiKey(result);
    await _initDashboard();
    if (!mounted || _dash == null) return;
    Navigator.pushAndRemoveUntil(
      context,
      MaterialPageRoute(builder: (_) => AdminApp(api: _dash!)),
      (_) => false,
    );
  }

  // ── Helpers ───────────────────────────────────────────────────────────────

  Color _severityClr(String s) => switch (s.toLowerCase()) {
    'critical' => const Color(0xFFEF4444),
    'high'     => const Color(0xFFF97316),
    'medium'   => const Color(0xFFF59E0B),
    _          => const Color(0xFF6B7280),
  };

  String _timeAgo(String? ts) {
    if (ts == null || ts.isEmpty) return 'never';
    try {
      final d = DateTime.parse(ts).toLocal();
      final diff = DateTime.now().difference(d);
      if (diff.inSeconds < 60) return 'just now';
      if (diff.inMinutes < 60) return '${diff.inMinutes}m ago';
      if (diff.inHours < 24)   return '${diff.inHours}h ago';
      return '${diff.inDays}d ago';
    } catch (_) { return ts; }
  }

  // ── Build ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        title: Row(children: [
          Icon(Icons.security, color: cs.primary, size: 20),
          const SizedBox(width: 8),
          const Text('XCloak', style: TextStyle(fontWeight: FontWeight.w700)),
        ]),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
            tooltip: 'Refresh',
            onPressed: () {
              _refreshAgent();
              if (_dashAvailable) _loadDashboard();
            },
          ),
          IconButton(
            icon: const Icon(Icons.admin_panel_settings),
            tooltip: 'Admin Mode',
            onPressed: _dashAvailable
                ? () => Navigator.pushAndRemoveUntil(
                      context,
                      MaterialPageRoute(builder: (_) => AdminApp(api: _dash!)),
                      (_) => false,
                    )
                : _enterAdminMode,
          ),
          PopupMenuButton<String>(
            onSelected: (v) { if (v == 'unenroll') _unenroll(); },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'unenroll', child: Text('Unenroll device')),
            ],
          ),
        ],
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(icon: Icon(Icons.shield_outlined), text: 'Agent'),
            Tab(icon: Icon(Icons.notifications_outlined), text: 'Alerts'),
            Tab(icon: Icon(Icons.devices_outlined), text: 'Agents'),
          ],
        ),
      ),
      body: TabBarView(
        controller: _tabs,
        children: [
          _AgentTab(
            serviceRunning: _serviceRunning,
            rooted: _rooted,
            devMode: _devMode,
            osVersion: _osVersion,
            deviceId: _deviceId,
            sideloaded: _sideloaded,
            onToggle: _toggleService,
            overview: _dashAvailable ? _overview : null,
          ),
          _AlertsTab(
            available: _dashAvailable,
            alerts: _alerts,
            loading: _dashLoading,
            filter: _alertFilter,
            onFilterChanged: (f) {
              setState(() => _alertFilter = f);
              _loadDashboard();
            },
            onAcknowledge: _dash == null ? null : (id) async {
              final ok = await _dash!.ackAlert(id);
              if (ok) _loadDashboard();
              return ok;
            },
            onResolve: _dash == null ? null : (id) async {
              final ok = await _dash!.resolveAlert(id);
              if (ok) _loadDashboard();
              return ok;
            },
            timeAgo: _timeAgo,
            severityColor: _severityClr,
          ),
          _AgentsTab(
            available: _dashAvailable,
            agents: _agents,
            loading: _dashLoading,
            timeAgo: _timeAgo,
            onTask: _dash == null ? null : (agentId, task) async {
              final ok = await _dash!.queueTask(agentId, task);
              if (!mounted) return;
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content: Text(ok ? 'Task queued' : 'Failed to queue task'),
                behavior: SnackBarBehavior.floating,
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
                duration: const Duration(seconds: 2),
              ));
            },
          ),
        ],
      ),
    );
  }
}

// ── Agent tab ─────────────────────────────────────────────────────────────────

class _AgentTab extends StatelessWidget {
  final bool serviceRunning;
  final bool rooted;
  final bool devMode;
  final String osVersion;
  final String? deviceId;
  final List<String> sideloaded;
  final VoidCallback onToggle;
  final Map<String, dynamic>? overview;

  const _AgentTab({
    required this.serviceRunning,
    required this.rooted,
    required this.devMode,
    required this.osVersion,
    required this.deviceId,
    required this.sideloaded,
    required this.onToggle,
    required this.overview,
  });

  @override
  Widget build(BuildContext context) {
    final cs  = Theme.of(context).colorScheme;
    final risk = rooted || sideloaded.isNotEmpty;

    return RefreshIndicator(
      onRefresh: () async {},
      child: ListView(
        padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
        children: [

          // ── Service card ───────────────────────────────────────────────
          _serviceCard(context, cs),
          const SizedBox(height: 10),

          // ── Risk banner ────────────────────────────────────────────────
          _riskBanner(context, cs, risk),
          const SizedBox(height: 10),

          // ── Overview grid ──────────────────────────────────────────────
          if (overview != null) ...[
            _sectionLabel(context, 'NGFW Overview'),
            const SizedBox(height: 8),
            _OverviewGrid(overview: overview!),
            const SizedBox(height: 10),
          ],

          // ── Device info ────────────────────────────────────────────────
          _sectionLabel(context, 'Device'),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.all(16),
              child: Column(children: [
                _infoRow(context, Icons.phone_android, 'OS Version', osVersion.isNotEmpty ? osVersion : '—'),
                const SizedBox(height: 10),
                _infoRow(context, Icons.fingerprint, 'Device ID', deviceId ?? '—'),
              ]),
            ),
          ),
          const SizedBox(height: 10),

          // ── Security checks ────────────────────────────────────────────
          _sectionLabel(context, 'Security'),
          const SizedBox(height: 8),
          Card(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
              child: Column(children: [
                _checkRow('Not Rooted / Jailbroken',     !rooted),
                _divider(),
                _checkRow('Developer Options Off',        !devMode),
                _divider(),
                _checkRow('No Sideloaded Apps',           sideloaded.isEmpty),
              ]),
            ),
          ),

          if (sideloaded.isNotEmpty) ...[
            const SizedBox(height: 10),
            _sectionLabel(context, 'Sideloaded Apps (${sideloaded.length})'),
            const SizedBox(height: 8),
            Card(
              child: Padding(
                padding: const EdgeInsets.all(12),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: sideloaded.take(15).map((p) => Padding(
                    padding: const EdgeInsets.symmetric(vertical: 3),
                    child: Row(children: [
                      Icon(Icons.warning_amber_rounded, size: 14, color: Colors.orange.shade700),
                      const SizedBox(width: 6),
                      Expanded(child: Text(p,
                          style: const TextStyle(fontFamily: 'monospace', fontSize: 11))),
                    ]),
                  )).toList(),
                ),
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _serviceCard(BuildContext context, ColorScheme cs) {
    final color = serviceRunning ? const Color(0xFF22C55E) : Colors.grey;
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Row(children: [
          Container(
            width: 48, height: 48,
            decoration: BoxDecoration(
              color: color.withOpacity(.12),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Icon(
              serviceRunning ? Icons.shield : Icons.shield_outlined,
              color: color, size: 24,
            ),
          ),
          const SizedBox(width: 14),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const Text('Agent Service',
                style: TextStyle(fontWeight: FontWeight.w600, fontSize: 15)),
            const SizedBox(height: 2),
            Text(
              serviceRunning ? 'Active — monitoring device' : 'Stopped',
              style: TextStyle(fontSize: 12,
                  color: serviceRunning ? const Color(0xFF22C55E) : Colors.grey),
            ),
          ])),
          Switch.adaptive(value: serviceRunning, onChanged: (_) => onToggle()),
        ]),
      ),
    );
  }

  Widget _riskBanner(BuildContext context, ColorScheme cs, bool risk) {
    final color   = risk ? const Color(0xFFF97316) : const Color(0xFF22C55E);
    final icon    = risk ? Icons.warning_amber_rounded : Icons.verified_user;
    final label   = risk ? 'Action Needed' : 'Device Secure';
    final sublabel = risk ? 'Security issues detected on this device' : 'All checks passed';
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(children: [
          Container(
            width: 40, height: 40,
            decoration: BoxDecoration(
              color: color.withOpacity(.12),
              borderRadius: BorderRadius.circular(10),
            ),
            child: Icon(icon, color: color, size: 20),
          ),
          const SizedBox(width: 12),
          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(label, style: TextStyle(fontWeight: FontWeight.w600, color: color, fontSize: 13)),
            Text(sublabel, style: TextStyle(fontSize: 11, color: color.withOpacity(.7))),
          ]),
        ]),
      ),
    );
  }

  Widget _infoRow(BuildContext context, IconData icon, String label, String value) {
    return Row(children: [
      Icon(icon, size: 16, color: Theme.of(context).colorScheme.primary.withOpacity(.6)),
      const SizedBox(width: 10),
      Text(label, style: TextStyle(fontSize: 12, color: Colors.grey.shade600)),
      const Spacer(),
      Text(value, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500)),
    ]);
  }

  Widget _checkRow(String label, bool passing) {
    final color = passing ? const Color(0xFF22C55E) : const Color(0xFFEF4444);
    final icon  = passing ? Icons.check_rounded : Icons.close_rounded;
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 8),
      child: Row(children: [
        Container(
          width: 26, height: 26,
          decoration: BoxDecoration(
            color: color.withOpacity(.12),
            borderRadius: BorderRadius.circular(7),
          ),
          child: Icon(icon, size: 14, color: color),
        ),
        const SizedBox(width: 10),
        Text(label, style: const TextStyle(fontSize: 13)),
        const Spacer(),
        Text(passing ? 'Pass' : 'Fail',
            style: TextStyle(fontSize: 11, fontWeight: FontWeight.w600, color: color)),
      ]),
    );
  }

  Widget _divider() => Divider(height: 1, color: Colors.grey.shade200);

  Widget _sectionLabel(BuildContext context, String text) => Text(
    text,
    style: TextStyle(
      fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 1.1,
      color: Theme.of(context).colorScheme.primary.withOpacity(.75),
    ),
  );
}

// ── Overview grid ─────────────────────────────────────────────────────────────

class _OverviewGrid extends StatelessWidget {
  final Map<String, dynamic> overview;
  const _OverviewGrid({required this.overview});

  @override
  Widget build(BuildContext context) {
    final items = [
      ('Agents Online', '${overview['agents_online'] ?? overview['online_agents'] ?? '—'}', const Color(0xFF22C55E)),
      ('Open Alerts',   '${overview['open_alerts']   ?? overview['active_alerts']  ?? '—'}', const Color(0xFFF97316)),
      ('Critical',      '${overview['critical_alerts'] ?? '—'}',                              const Color(0xFFEF4444)),
      ('Incidents',     '${overview['active_incidents'] ?? overview['open_incidents'] ?? '—'}', const Color(0xFF3B82F6)),
    ];
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      childAspectRatio: 2.4,
      mainAxisSpacing: 8,
      crossAxisSpacing: 8,
      children: items.map((e) => Card(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Row(children: [
            Container(width: 4, height: 32,
                decoration: BoxDecoration(color: e.$3, borderRadius: BorderRadius.circular(2))),
            const SizedBox(width: 8),
            Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
              Text(e.$2, style: TextStyle(fontSize: 20, fontWeight: FontWeight.w700, color: e.$3, height: 1)),
              Text(e.$1, style: const TextStyle(fontSize: 10, color: Colors.grey)),
            ]),
          ]),
        ),
      )).toList(),
    );
  }
}

// ── Alerts tab ────────────────────────────────────────────────────────────────

class _AlertsTab extends StatelessWidget {
  final bool available;
  final List<dynamic> alerts;
  final bool loading;
  final String filter;
  final void Function(String) onFilterChanged;
  final Future<bool> Function(int)? onAcknowledge;
  final Future<bool> Function(int)? onResolve;
  final String Function(String?) timeAgo;
  final Color Function(String) severityColor;

  const _AlertsTab({
    required this.available,
    required this.alerts,
    required this.loading,
    required this.filter,
    required this.onFilterChanged,
    required this.onAcknowledge,
    required this.onResolve,
    required this.timeAgo,
    required this.severityColor,
  });

  @override
  Widget build(BuildContext context) {
    if (!available) {
      return _NoApiKeyPlaceholder(
        icon: Icons.notifications_none,
        label: 'Alerts require an Admin API Key.',
      );
    }

    return Column(
      children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                for (final f in [('All', ''), ('Critical', 'critical'), ('High', 'high'), ('Medium', 'medium')])
                  Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: FilterChip(
                      label: Text(f.$1),
                      selected: filter == f.$2,
                      onSelected: (_) => onFilterChanged(f.$2),
                    ),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 6),
        if (loading && alerts.isEmpty)
          const Expanded(child: Center(child: CircularProgressIndicator(strokeWidth: 2)))
        else if (alerts.isEmpty)
          Expanded(
            child: Center(
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                Icon(Icons.notifications_none, size: 48, color: Colors.grey.shade400),
                const SizedBox(height: 12),
                Text('No alerts', style: TextStyle(color: Colors.grey.shade500)),
              ]),
            ),
          )
        else
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 4, 12, 16),
              itemCount: alerts.length,
              itemBuilder: (ctx, i) {
                final a   = alerts[i] as Map<String, dynamic>;
                final sev = (a['severity'] ?? '').toString();
                final sta = (a['status']   ?? '').toString();
                final col = severityColor(sev);
                return Padding(
                  padding: const EdgeInsets.only(bottom: 8),
                  child: Card(
                    child: IntrinsicHeight(
                      child: Row(children: [
                        Container(
                          width: 4,
                          decoration: BoxDecoration(
                            color: col,
                            borderRadius: const BorderRadius.only(
                              topLeft: Radius.circular(12),
                              bottomLeft: Radius.circular(12),
                            ),
                          ),
                        ),
                        Expanded(
                          child: Padding(
                            padding: const EdgeInsets.fromLTRB(12, 10, 8, 10),
                            child: Row(children: [
                              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                                Text(
                                  (a['rule_name'] ?? a['message'] ?? 'Alert').toString(),
                                  maxLines: 2, overflow: TextOverflow.ellipsis,
                                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                                ),
                                const SizedBox(height: 4),
                                Row(children: [
                                  _sevPill(sev, col),
                                  const SizedBox(width: 6),
                                  Text(timeAgo(a['created_at']?.toString()),
                                      style: TextStyle(fontSize: 11, color: Colors.grey.shade500)),
                                  if (a['hostname'] != null) ...[
                                    Text('  ·  ',
                                        style: TextStyle(color: Colors.grey.shade400)),
                                    Flexible(child: Text(a['hostname'].toString(),
                                        style: TextStyle(fontSize: 11, color: Colors.grey.shade500),
                                        overflow: TextOverflow.ellipsis)),
                                  ],
                                ]),
                              ])),
                              if (sta == 'open' && (onAcknowledge != null || onResolve != null))
                                PopupMenuButton<String>(
                                  onSelected: (v) {
                                    if (v == 'ack')    onAcknowledge?.call(a['id'] as int);
                                    if (v == 'resolve') onResolve?.call(a['id'] as int);
                                  },
                                  itemBuilder: (_) => [
                                    if (onAcknowledge != null)
                                      const PopupMenuItem(value: 'ack',     child: Text('Acknowledge')),
                                    if (onResolve != null)
                                      const PopupMenuItem(value: 'resolve', child: Text('Resolve')),
                                  ],
                                )
                              else
                                Padding(
                                  padding: const EdgeInsets.only(right: 4),
                                  child: Text(sta,
                                      style: TextStyle(fontSize: 11, color: Colors.grey.shade500)),
                                ),
                            ]),
                          ),
                        ),
                      ]),
                    ),
                  ),
                );
              },
            ),
          ),
      ],
    );
  }

  Widget _sevPill(String sev, Color col) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
    decoration: BoxDecoration(
      color: col.withOpacity(.12),
      borderRadius: BorderRadius.circular(20),
    ),
    child: Text(sev.toUpperCase(),
        style: TextStyle(fontSize: 9, fontWeight: FontWeight.w700, color: col, letterSpacing: .4)),
  );
}

// ── Agents tab ────────────────────────────────────────────────────────────────

const _AGENT_TASKS = [
  ('collect_processes',   'Collect Processes'),
  ('collect_connections', 'Collect Connections'),
  ('collect_packages',    'Collect Packages'),
  ('vulnerability_scan',  'Vulnerability Scan'),
  ('collect_file_hashes', 'Scan File Hashes'),
  ('isolate_host',        'Isolate Host'),
];

class _AgentsTab extends StatelessWidget {
  final bool available;
  final List<dynamic> agents;
  final bool loading;
  final String Function(String?) timeAgo;
  final void Function(int agentId, String task)? onTask;

  const _AgentsTab({
    required this.available,
    required this.agents,
    required this.loading,
    required this.timeAgo,
    required this.onTask,
  });

  @override
  Widget build(BuildContext context) {
    if (!available) {
      return _NoApiKeyPlaceholder(
        icon: Icons.phone_android_outlined,
        label: 'Agent control requires an Admin API Key.',
      );
    }

    if (loading && agents.isEmpty) {
      return const Center(child: CircularProgressIndicator(strokeWidth: 2));
    }
    if (agents.isEmpty) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.devices_outlined, size: 48, color: Colors.grey.shade400),
          const SizedBox(height: 12),
          Text('No agents', style: TextStyle(color: Colors.grey.shade500)),
        ]),
      );
    }

    return ListView.builder(
      padding: const EdgeInsets.fromLTRB(12, 12, 12, 16),
      itemCount: agents.length,
      itemBuilder: (ctx, i) {
        final a       = agents[i] as Map<String, dynamic>;
        final online  = (a['status'] ?? '') == 'online';
        final agentId = a['id'] as int? ?? 0;
        final os      = (a['os'] ?? a['platform'] ?? '').toString().toLowerCase();

        return Padding(
          padding: const EdgeInsets.only(bottom: 8),
          child: Card(
            child: ListTile(
              contentPadding: const EdgeInsets.fromLTRB(14, 8, 8, 8),
              leading: Stack(
                clipBehavior: Clip.none,
                children: [
                  Container(
                    width: 40, height: 40,
                    decoration: BoxDecoration(
                      color: (online ? const Color(0xFF22C55E) : Colors.grey).withOpacity(.1),
                      borderRadius: BorderRadius.circular(10),
                    ),
                    child: Icon(
                      _osIcon(os),
                      color: online ? const Color(0xFF22C55E) : Colors.grey,
                      size: 20,
                    ),
                  ),
                  Positioned(
                    right: -2, bottom: -2,
                    child: Container(
                      width: 11, height: 11,
                      decoration: BoxDecoration(
                        color: online ? const Color(0xFF22C55E) : Colors.grey.shade400,
                        shape: BoxShape.circle,
                        border: Border.all(color: Theme.of(ctx).colorScheme.surface, width: 2),
                      ),
                    ),
                  ),
                ],
              ),
              title: Text(
                (a['hostname'] ?? 'Agent $agentId').toString(),
                style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 14),
              ),
              subtitle: Padding(
                padding: const EdgeInsets.only(top: 2),
                child: Text(
                  '${os.toUpperCase().isEmpty ? '—' : os.toUpperCase()}'
                  '  ·  ${a['ip_address'] ?? '—'}'
                  '  ·  ${timeAgo(a['last_seen']?.toString())}',
                  style: TextStyle(fontSize: 11, color: Colors.grey.shade500),
                ),
              ),
              trailing: onTask != null
                ? PopupMenuButton<String>(
                    onSelected: (task) => onTask!(agentId, task),
                    itemBuilder: (_) => _AGENT_TASKS
                        .map((t) => PopupMenuItem(value: t.$1, child: Text(t.$2)))
                        .toList(),
                  )
                : null,
            ),
          ),
        );
      },
    );
  }

  IconData _osIcon(String os) {
    if (os.contains('windows')) return Icons.laptop_windows;
    if (os.contains('mac') || os.contains('darwin')) return Icons.laptop_mac;
    if (os.contains('android')) return Icons.phone_android;
    if (os.contains('ios')) return Icons.phone_iphone;
    return Icons.computer;
  }
}

// ── Shared placeholder ────────────────────────────────────────────────────────

class _NoApiKeyPlaceholder extends StatelessWidget {
  final IconData icon;
  final String label;
  const _NoApiKeyPlaceholder({required this.icon, required this.label});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(
            width: 72, height: 72,
            decoration: BoxDecoration(
              color: cs.primary.withOpacity(.07),
              borderRadius: BorderRadius.circular(36),
            ),
            child: Icon(icon, size: 30, color: cs.primary.withOpacity(.4)),
          ),
          const SizedBox(height: 16),
          Text(label,
              textAlign: TextAlign.center,
              style: TextStyle(fontSize: 14, fontWeight: FontWeight.w500,
                  color: cs.onSurface.withOpacity(.55))),
          const SizedBox(height: 8),
          Text(
            'Tap  to enter an Admin API Key.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: cs.onSurface.withOpacity(.35)),
          ),
        ]),
      ),
    );
  }
}
