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

  String _alertFilter = '';  // '' | 'critical' | 'high'

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
      // back-fill overview incident count if the overview API didn't include it
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
            border: OutlineInputBorder(),
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

  Color _severityClr(String s) {
    switch (s.toLowerCase()) {
      case 'critical': return Colors.red;
      case 'high':     return Colors.orange;
      case 'medium':   return Colors.yellow.shade700;
      default:         return Colors.grey;
    }
  }

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

  // ── Tabs ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('XCloak'),
        actions: [
          IconButton(
            icon: const Icon(Icons.refresh),
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
            onSelected: (v) {
              if (v == 'unenroll') _unenroll();
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'unenroll', child: Text('Unenroll device')),
            ],
          ),
        ],
        bottom: TabBar(
          controller: _tabs,
          tabs: const [
            Tab(icon: Icon(Icons.shield), text: 'Agent'),
            Tab(icon: Icon(Icons.notifications), text: 'Alerts'),
            Tab(icon: Icon(Icons.devices), text: 'Agents'),
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
              ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                content: Text(ok ? 'Task queued' : 'Failed to queue task'),
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
    final risk = rooted || sideloaded.isNotEmpty;

    return RefreshIndicator(
      onRefresh: () async {},
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // ── Service toggle ───────────────────────────────────────────
          Card(
            child: ListTile(
              leading: Icon(serviceRunning ? Icons.shield : Icons.shield_outlined,
                  color: serviceRunning ? Colors.green : Colors.grey, size: 32),
              title: const Text('Agent Service', style: TextStyle(fontWeight: FontWeight.bold)),
              subtitle: Text(serviceRunning ? 'Active — monitoring' : 'Stopped',
                  style: TextStyle(color: serviceRunning ? Colors.green : Colors.grey)),
              trailing: Switch(value: serviceRunning, onChanged: (_) => onToggle()),
            ),
          ),
          const SizedBox(height: 10),

          // ── Risk level ───────────────────────────────────────────────
          Card(
            child: ListTile(
              leading: Icon(risk ? Icons.warning_amber : Icons.check_circle,
                  color: risk ? Colors.orange : Colors.green, size: 32),
              title: const Text('Risk Level', style: TextStyle(fontWeight: FontWeight.bold)),
              subtitle: Text(risk ? 'Action needed' : 'All clear',
                  style: TextStyle(color: risk ? Colors.orange : Colors.green)),
            ),
          ),
          const SizedBox(height: 10),

          // ── Dashboard overview (if API key provided) ─────────────────
          if (overview != null) ...[
            _SectionHeader('NGFW Overview'),
            const SizedBox(height: 8),
            _OverviewGrid(overview: overview!),
            const SizedBox(height: 10),
          ],

          // ── Device info ──────────────────────────────────────────────
          _InfoCard(title: 'Device Info', children: [
            _Row('OS Version', osVersion),
            _Row('Device ID', deviceId ?? '—'),
          ]),
          const SizedBox(height: 10),

          // ── Security checks ──────────────────────────────────────────
          _InfoCard(title: 'Security Checks', children: [
            _Check('Not Rooted / Jailbroken', !rooted),
            _Check('Developer Options Off', !devMode),
            _Check('No Sideloaded Apps', sideloaded.isEmpty),
          ]),

          if (sideloaded.isNotEmpty) ...[
            const SizedBox(height: 10),
            _InfoCard(
              title: 'Sideloaded Apps (${sideloaded.length})',
              children: sideloaded
                  .take(15)
                  .map((p) => Padding(
                        padding: const EdgeInsets.symmetric(vertical: 2),
                        child: Text(p,
                            style: const TextStyle(
                                fontFamily: 'monospace', fontSize: 12)),
                      ))
                  .toList(),
            ),
          ],
          const SizedBox(height: 24),
        ],
      ),
    );
  }
}

class _OverviewGrid extends StatelessWidget {
  final Map<String, dynamic> overview;
  const _OverviewGrid({required this.overview});

  @override
  Widget build(BuildContext context) {
    final items = [
      ('Agents Online', '${overview['agents_online'] ?? overview['online_agents'] ?? '—'}', Colors.green),
      ('Open Alerts', '${overview['open_alerts'] ?? overview['active_alerts'] ?? '—'}', Colors.orange),
      ('Critical', '${overview['critical_alerts'] ?? '—'}', Colors.red),
      ('Incidents', '${overview['active_incidents'] ?? overview['open_incidents'] ?? '—'}', Colors.blue),
    ];
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      childAspectRatio: 2.2,
      mainAxisSpacing: 8,
      crossAxisSpacing: 8,
      children: items.map((e) => Card(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(e.$3 == Colors.red ? '${e.$2}' : e.$2,
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: e.$3)),
              Text(e.$1, style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ],
          ),
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
        // Filter chips
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
          child: SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(
              children: [
                for (final f in ['', 'critical', 'high', 'medium'])
                  Padding(
                    padding: const EdgeInsets.only(right: 6),
                    child: FilterChip(
                      label: Text(f.isEmpty ? 'All' : f[0].toUpperCase() + f.substring(1)),
                      selected: filter == f,
                      onSelected: (_) => onFilterChanged(f),
                    ),
                  ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 4),
        if (loading && alerts.isEmpty)
          const Expanded(child: Center(child: CircularProgressIndicator()))
        else if (alerts.isEmpty)
          const Expanded(
            child: Center(
              child: Text('No alerts', style: TextStyle(color: Colors.grey)),
            ),
          )
        else
          Expanded(
            child: ListView.builder(
              padding: const EdgeInsets.all(8),
              itemCount: alerts.length,
              itemBuilder: (ctx, i) {
                final a   = alerts[i] as Map<String, dynamic>;
                final sev = (a['severity'] ?? '').toString();
                final sta = (a['status']   ?? '').toString();
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: CircleAvatar(
                      radius: 6,
                      backgroundColor: severityColor(sev),
                    ),
                    title: Text(
                      (a['rule_name'] ?? a['message'] ?? 'Alert').toString(),
                      maxLines: 2,
                      overflow: TextOverflow.ellipsis,
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                    ),
                    subtitle: Text(
                      '${sev.toUpperCase()}  ·  ${timeAgo(a['created_at']?.toString())}'
                      '${a['hostname'] != null ? "  ·  ${a['hostname']}" : ""}',
                      style: const TextStyle(fontSize: 11),
                    ),
                    trailing: sta == 'open' && (onAcknowledge != null || onResolve != null)
                      ? PopupMenuButton<String>(
                          onSelected: (v) {
                            if (v == 'ack')     onAcknowledge?.call(a['id'] as int);
                            if (v == 'resolve')  onResolve?.call(a['id'] as int);
                          },
                          itemBuilder: (_) => [
                            if (onAcknowledge != null)
                              const PopupMenuItem(value: 'ack',     child: Text('Acknowledge')),
                            if (onResolve != null)
                              const PopupMenuItem(value: 'resolve', child: Text('Resolve')),
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
      return const Center(child: CircularProgressIndicator());
    }
    if (agents.isEmpty) {
      return const Center(child: Text('No agents', style: TextStyle(color: Colors.grey)));
    }

    return ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: agents.length,
      itemBuilder: (ctx, i) {
        final a       = agents[i] as Map<String, dynamic>;
        final online  = (a['status'] ?? '') == 'online';
        final agentId = a['id'] as int? ?? 0;

        return Card(
          margin: const EdgeInsets.only(bottom: 8),
          child: ListTile(
            leading: Icon(
              Icons.computer,
              color: online ? Colors.green : Colors.grey,
            ),
            title: Text(
              (a['hostname'] ?? 'Agent $agentId').toString(),
              style: const TextStyle(fontWeight: FontWeight.w600),
            ),
            subtitle: Text(
              '${(a['os'] ?? a['platform'] ?? '').toString().toUpperCase()}'
              '  ·  ${a['ip_address'] ?? '—'}'
              '  ·  ${timeAgo(a['last_seen']?.toString())}',
              style: const TextStyle(fontSize: 11),
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
        );
      },
    );
  }
}

// ── Shared widgets ────────────────────────────────────────────────────────────

class _NoApiKeyPlaceholder extends StatelessWidget {
  final IconData icon;
  final String label;
  const _NoApiKeyPlaceholder({required this.icon, required this.label});

  @override
  Widget build(BuildContext context) {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 48, color: Colors.grey),
          const SizedBox(height: 12),
          Text(label, style: const TextStyle(color: Colors.grey)),
          const SizedBox(height: 8),
          const Text(
            'Unenroll and re-enroll with an API Key\nfrom Settings → API Keys in the dashboard.',
            textAlign: TextAlign.center,
            style: TextStyle(fontSize: 12, color: Colors.grey),
          ),
        ],
      ),
    );
  }
}

class _SectionHeader extends StatelessWidget {
  final String text;
  const _SectionHeader(this.text);
  @override
  Widget build(BuildContext context) => Text(
        text,
        style: TextStyle(
          fontSize: 11,
          fontWeight: FontWeight.bold,
          letterSpacing: 1.2,
          color: Theme.of(context).colorScheme.primary,
        ),
      );
}

class _InfoCard extends StatelessWidget {
  final String title;
  final List<Widget> children;
  const _InfoCard({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title,
                style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
            const Divider(height: 12),
            ...children,
          ],
        ),
      ),
    );
  }
}

Widget _Row(String label, String value) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(children: [
        Expanded(flex: 2, child: Text(label, style: const TextStyle(color: Colors.grey, fontSize: 13))),
        Expanded(flex: 3, child: Text(value, style: const TextStyle(fontSize: 13))),
      ]),
    );

Widget _Check(String label, bool passing) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 3),
      child: Row(children: [
        Icon(passing ? Icons.check_circle : Icons.cancel,
            color: passing ? Colors.green : Colors.red, size: 16),
        const SizedBox(width: 8),
        Text(label, style: const TextStyle(fontSize: 13)),
      ]),
    );
