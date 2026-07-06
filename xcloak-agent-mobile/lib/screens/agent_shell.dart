import 'package:flutter/material.dart';
import 'package:flutter_background_service/flutter_background_service.dart';

import '../models/device_posture.dart';
import '../services/api_client.dart';
import '../services/posture_collector.dart';
import '../services/secure_storage.dart';
import '../services/threat_detector.dart';
import '../admin/api.dart';
import 'admin_login.dart';
import '../admin/shell.dart';
import 'setup_screen.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Shell
// ─────────────────────────────────────────────────────────────────────────────

class AgentShell extends StatefulWidget {
  const AgentShell({super.key});
  @override State<AgentShell> createState() => _AgentShellState();
}

class _AgentShellState extends State<AgentShell> {
  int _tab = 0;
  bool _checkingAdmin = false;

  Future<void> _openAdminConsole() async {
    setState(() => _checkingAdmin = true);
    try {
      // Try to restore an existing valid session first
      final api = await DashboardApi.createFromSession();
      if (!mounted) return;
      if (api != null) {
        Navigator.push(context, MaterialPageRoute(builder: (_) => AdminApp(api: api)));
      } else {
        Navigator.push(context, MaterialPageRoute(builder: (_) => const AdminLoginScreen()));
      }
    } finally {
      if (mounted) setState(() => _checkingAdmin = false);
    }
  }

  Future<void> _unenroll() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Unenroll Device'),
        content: const Text('This will remove all credentials and reset the app. Continue?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(context, true), child: const Text('Unenroll')),
        ],
      ),
    );
    if (ok != true) return;
    await SecureStore.clear();
    if (!mounted) return;
    Navigator.pushAndRemoveUntil(
      context,
      MaterialPageRoute(builder: (_) => const SetupScreen()),
      (_) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    final tabs = [
      const _HomeTab(),
      const _ThreatsTab(),
      const _PostureTab(),
      const _ActivityTab(),
    ];

    return Scaffold(
      appBar: AppBar(
        titleSpacing: 12,
        title: Row(
          children: [
            Container(
              width: 30, height: 30,
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(8),
                color: cs.primary.withOpacity(.12),
                border: Border.all(color: cs.primary.withOpacity(.25)),
              ),
              child: Icon(Icons.security, color: cs.primary, size: 17),
            ),
            const SizedBox(width: 10),
            const Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text('XCloak Agent', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w700, height: 1.2)),
                Text('Mobile Security', style: TextStyle(fontSize: 10, color: Colors.grey, height: 1.2)),
              ],
            ),
          ],
        ),
        actions: [
          if (_checkingAdmin)
            const Padding(
              padding: EdgeInsets.only(right: 16),
              child: SizedBox(width: 20, height: 20, child: CircularProgressIndicator(strokeWidth: 2)),
            )
          else
            IconButton(
              icon: Icon(Icons.admin_panel_settings_outlined, color: cs.primary),
              tooltip: 'Admin Console',
              onPressed: _openAdminConsole,
            ),
          PopupMenuButton<String>(
            onSelected: (v) { if (v == 'unenroll') _unenroll(); },
            itemBuilder: (_) => [
              const PopupMenuItem(value: 'unenroll', child: Row(children: [
                Icon(Icons.logout, size: 16, color: Colors.redAccent),
                SizedBox(width: 8),
                Text('Unenroll Device', style: TextStyle(color: Colors.redAccent)),
              ])),
            ],
          ),
        ],
      ),
      body: tabs[_tab],
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        labelBehavior: NavigationDestinationLabelBehavior.onlyShowSelected,
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.home_outlined),
            selectedIcon: Icon(Icons.home),
            label: 'Home',
          ),
          NavigationDestination(
            icon: Icon(Icons.warning_amber_outlined),
            selectedIcon: Icon(Icons.warning_amber),
            label: 'Threats',
          ),
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'Posture',
          ),
          NavigationDestination(
            icon: Icon(Icons.history_outlined),
            selectedIcon: Icon(Icons.history),
            label: 'Activity',
          ),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 0 — Home
// ─────────────────────────────────────────────────────────────────────────────

class _HomeTab extends StatefulWidget {
  const _HomeTab();
  @override State<_HomeTab> createState() => _HomeTabState();
}

class _HomeTabState extends State<_HomeTab> with AutomaticKeepAliveClientMixin {
  @override bool get wantKeepAlive => true;

  bool _loading = true;
  bool _serviceRunning = false;
  bool _serverConnected = false;
  DevicePosture? _posture;
  List<String> _sideloaded = [];
  int? _agentId;
  String? _serverUrl;
  String? _deviceModel;
  int _threatCount = 0;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final running    = await FlutterBackgroundService().isRunning();
      final posture    = await PostureCollector.collect();
      final sideloaded = await ThreatDetector.sideloadedPackages();
      final serverUrl  = await SecureStore.serverUrl();
      final agentId    = await SecureStore.agentId();
      final model      = await PostureCollector.model();

      bool connected = false;
      int threats    = 0;
      if (serverUrl != null && agentId != null) {
        try {
          final c   = await ApiClient.fromStorage();
          final res = await c.get('/api/agents/$agentId/summary');
          final alerts = (res['recent_alerts'] ?? res['alerts']) as List? ?? [];
          threats   = alerts.length;
          connected = true;
        } catch (_) {}
      }

      if (!mounted) return;
      setState(() {
        _loading = false;
        _serviceRunning = running;
        _posture        = posture;
        _sideloaded     = sideloaded;
        _serverUrl      = serverUrl;
        _agentId        = agentId;
        _deviceModel    = model;
        _serverConnected = connected;
        _threatCount    = threats;
      });
    } catch (_) {
      if (mounted) setState(() => _loading = false);
    }
  }

  _StatusLevel get _level {
    if (_posture?.isRooted == true) return _StatusLevel.compromised;
    if (_threatCount > 0) return _StatusLevel.alert;
    if (_sideloaded.isNotEmpty || (_posture?.developerModeOn == true)) return _StatusLevel.warning;
    if (!_serviceRunning || !_serverConnected) return _StatusLevel.monitoring;
    return _StatusLevel.protected;
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (_loading) return const Center(child: CircularProgressIndicator());
    final cs    = Theme.of(context).colorScheme;
    final level = _level;
    final color = level.color;

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 20),
        children: [
          // ── Protection ring ───────────────────────────────
          Center(
            child: Stack(
              alignment: Alignment.center,
              children: [
                SizedBox(
                  width: 190, height: 190,
                  child: CircularProgressIndicator(
                    value: level.progress,
                    backgroundColor: color.withOpacity(.12),
                    valueColor: AlwaysStoppedAnimation(color),
                    strokeWidth: 10,
                    strokeCap: StrokeCap.round,
                  ),
                ),
                Column(mainAxisSize: MainAxisSize.min, children: [
                  Icon(level.icon, color: color, size: 42),
                  const SizedBox(height: 8),
                  Text(level.label,
                    style: TextStyle(color: color, fontSize: 14, fontWeight: FontWeight.w800, letterSpacing: 1.8)),
                  if (_agentId != null) ...[
                    const SizedBox(height: 4),
                    Text('ID: XCL-${_agentId!.toString().padLeft(4, '0')}',
                      style: TextStyle(fontSize: 11.5, color: cs.onSurfaceVariant)),
                  ],
                ]),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // ── Stat chips ───────────────────────────────────
          Row(children: [
            _StatChip(value: '$_threatCount', label: 'Threats',
              color: _threatCount > 0 ? const Color(0xFFEF4444) : const Color(0xFF22C55E)),
            const SizedBox(width: 8),
            _StatChip(value: _complianceScore, label: 'Compliant',
              color: _posture?.isRooted == true ? const Color(0xFFEF4444) : const Color(0xFF22C55E)),
            const SizedBox(width: 8),
            _StatChip(
              value: _serviceRunning ? 'Active' : 'Stopped',
              label: 'Service',
              color: _serviceRunning ? const Color(0xFF22C55E) : const Color(0xFFEF4444),
            ),
          ]),
          const SizedBox(height: 20),

          // ── Status cards ─────────────────────────────────
          _StatusCard(
            icon: _serverConnected ? Icons.cloud_done_outlined : Icons.cloud_off_outlined,
            title: 'Server Connection',
            value: _serverConnected
              ? (_serverUrl?.replaceAll(RegExp(r'https?://'), '') ?? '—')
              : 'Disconnected',
            color: _serverConnected ? const Color(0xFF22C55E) : const Color(0xFFEF4444),
          ),
          const SizedBox(height: 8),
          _StatusCard(
            icon: _serviceRunning ? Icons.shield : Icons.shield_outlined,
            title: 'Background Protection',
            value: _serviceRunning ? 'Running' : 'Stopped — tap to start',
            color: _serviceRunning ? const Color(0xFF22C55E) : const Color(0xFFEF4444),
            onTap: _serviceRunning ? null : () async {
              await FlutterBackgroundService().startService();
              _load();
            },
          ),
          const SizedBox(height: 8),
          if (_deviceModel != null)
            _StatusCard(
              icon: Icons.phone_android_outlined,
              title: 'Device',
              value: _deviceModel!,
              color: cs.primary,
            ),
          const SizedBox(height: 8),
          if (_posture != null)
            _StatusCard(
              icon: Icons.android,
              title: 'OS Version',
              value: _posture!.osVersion,
              color: cs.primary,
            ),
          const SizedBox(height: 24),

          // ── Quick actions ─────────────────────────────────
          Text('Quick Actions',
            style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700,
              color: Theme.of(context).colorScheme.onSurfaceVariant, letterSpacing: 1.2)),
          const SizedBox(height: 10),
          Row(children: [
            _ActionButton(
              icon: Icons.send_outlined,
              label: 'Force Check-in',
              onTap: () async {
                final agentId   = await SecureStore.agentId();
                final serverUrl = await SecureStore.serverUrl();
                if (agentId == null || serverUrl == null) return;
                try {
                  final c = await ApiClient.fromStorage();
                  await c.post('/api/agents/$agentId/checkin', {});
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Check-in sent'), backgroundColor: Color(0xFF22C55E)));
                } catch (_) {
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Check-in failed'), backgroundColor: Color(0xFFEF4444)));
                }
              },
            ),
            const SizedBox(width: 8),
            _ActionButton(
              icon: Icons.bug_report_outlined,
              label: 'Scan Threats',
              onTap: () async {
                final agentId = await SecureStore.agentId();
                if (agentId == null) return;
                try {
                  final c = await ApiClient.fromStorage();
                  await c.post('/api/agents/$agentId/tasks', {'task_type': 'vulnerability_scan'});
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Scan dispatched'), backgroundColor: Color(0xFF22C55E)));
                } catch (_) {}
              },
            ),
            const SizedBox(width: 8),
            _ActionButton(
              icon: Icons.refresh,
              label: 'Refresh',
              onTap: _load,
            ),
          ]),
        ],
      ),
    );
  }

  String get _complianceScore {
    if (_posture == null) return '—';
    int score = 100;
    if (_posture!.isRooted) score -= 40;
    if (_posture!.developerModeOn) score -= 20;
    if (_sideloaded.isNotEmpty) score -= _sideloaded.length * 10;
    return '${score.clamp(0, 100)}%';
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 1 — Threats
// ─────────────────────────────────────────────────────────────────────────────

class _ThreatsTab extends StatefulWidget {
  const _ThreatsTab();
  @override State<_ThreatsTab> createState() => _ThreatsTabState();
}

class _ThreatsTabState extends State<_ThreatsTab> {
  bool _loading = true;
  List _alerts  = [];
  List<String> _sideloaded = [];

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final sideloaded = await ThreatDetector.sideloadedPackages();
    final agentId    = await SecureStore.agentId();
    List serverAlerts = [];
    if (agentId != null) {
      try {
        final c = await ApiClient.fromStorage();
        final r = await c.get('/api/alerts?agent_id=$agentId&per_page=50');
        serverAlerts = (r['data'] ?? r['alerts'] ?? r['items'] ?? []) as List;
      } catch (_) {}
    }
    if (!mounted) return;
    setState(() { _loading = false; _alerts = serverAlerts; _sideloaded = sideloaded; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    final localThreats = [
      for (final app in _sideloaded)
        {'title': 'Sideloaded App: $app', 'severity': 'high', 'description': 'Installed outside official app store'}
    ];
    final all = [...localThreats, ..._alerts];

    if (all.isEmpty) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.verified_user, size: 72, color: const Color(0xFF22C55E).withOpacity(.4)),
          const SizedBox(height: 16),
          const Text('No Threats Detected', style: TextStyle(fontSize: 17, fontWeight: FontWeight.w700)),
          const SizedBox(height: 6),
          Text('This device is clean', style: TextStyle(color: Colors.grey.shade500, fontSize: 13)),
        ]),
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(12),
        itemCount: all.length + 1,
        itemBuilder: (_, i) {
          if (i == 0) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: Row(children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 5),
                  decoration: BoxDecoration(
                    color: const Color(0xFFEF4444).withOpacity(.1),
                    borderRadius: BorderRadius.circular(20),
                    border: Border.all(color: const Color(0xFFEF4444).withOpacity(.3)),
                  ),
                  child: Text('${all.length} active ${all.length == 1 ? 'threat' : 'threats'}',
                    style: const TextStyle(color: Color(0xFFEF4444), fontSize: 12, fontWeight: FontWeight.w600)),
                ),
              ]),
            );
          }
          final t   = all[i - 1] as Map<String, dynamic>;
          final sev = (t['severity'] ?? 'low').toString().toLowerCase();
          final col = _sevColor(sev);
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: ListTile(
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              leading: Container(
                width: 42, height: 42,
                decoration: BoxDecoration(
                  color: col.withOpacity(.12),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: col.withOpacity(.3)),
                ),
                child: Icon(Icons.warning_amber, color: col, size: 22),
              ),
              title: Row(children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: col.withOpacity(.12),
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Text(sev.toUpperCase(),
                    style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800, color: col, letterSpacing: .8)),
                ),
                const SizedBox(width: 8),
                Expanded(child: Text(
                  (t['title'] ?? t['name'] ?? t['rule_name'] ?? 'Threat Detected').toString(),
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                  overflow: TextOverflow.ellipsis,
                )),
              ]),
              subtitle: Padding(
                padding: const EdgeInsets.only(top: 3),
                child: Text(
                  (t['description'] ?? t['message'] ?? '').toString(),
                  style: const TextStyle(fontSize: 11.5),
                  maxLines: 2,
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              isThreeLine: true,
            ),
          );
        },
      ),
    );
  }

  Color _sevColor(String s) => switch (s) {
    'critical' => const Color(0xFFEF4444),
    'high'     => const Color(0xFFF97316),
    'medium'   => const Color(0xFFF59E0B),
    _          => const Color(0xFF22C55E),
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 2 — Posture
// ─────────────────────────────────────────────────────────────────────────────

class _PostureTab extends StatefulWidget {
  const _PostureTab();
  @override State<_PostureTab> createState() => _PostureTabState();
}

class _PostureTabState extends State<_PostureTab> {
  bool _loading     = true;
  DevicePosture? _posture;
  List<String> _sideloaded = [];

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final p = await PostureCollector.collect();
    final s = await ThreatDetector.sideloadedPackages();
    if (!mounted) return;
    setState(() { _loading = false; _posture = p; _sideloaded = s; });
  }

  int get _score {
    if (_posture == null) return 0;
    int s = 100;
    if (_posture!.isRooted) s -= 40;
    if (_posture!.developerModeOn) s -= 20;
    if (_sideloaded.isNotEmpty) s -= (_sideloaded.length * 10).clamp(0, 30);
    return s.clamp(0, 100);
  }

  Color get _scoreColor {
    final s = _score;
    if (s >= 90) return const Color(0xFF22C55E);
    if (s >= 70) return const Color(0xFFF59E0B);
    return const Color(0xFFEF4444);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    final p = _posture;
    final cs = Theme.of(context).colorScheme;

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Score card
          Card(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    const Text('POSTURE SCORE', style: TextStyle(fontSize: 11, letterSpacing: 1.2, color: Colors.grey)),
                    const SizedBox(height: 4),
                    Text('$_score / 100',
                      style: TextStyle(fontSize: 30, fontWeight: FontWeight.w800, color: _scoreColor)),
                    Text(_score >= 90 ? 'Excellent' : _score >= 70 ? 'Fair' : 'At Risk',
                      style: TextStyle(fontSize: 13, color: _scoreColor, fontWeight: FontWeight.w600)),
                  ]),
                  const Spacer(),
                  SizedBox(
                    width: 68, height: 68,
                    child: Stack(alignment: Alignment.center, children: [
                      CircularProgressIndicator(
                        value: _score / 100,
                        backgroundColor: _scoreColor.withOpacity(.15),
                        valueColor: AlwaysStoppedAnimation(_scoreColor),
                        strokeWidth: 7,
                        strokeCap: StrokeCap.round,
                      ),
                      Text('$_score', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800, color: _scoreColor)),
                    ]),
                  ),
                ]),
                const SizedBox(height: 16),
                ClipRRect(
                  borderRadius: BorderRadius.circular(6),
                  child: LinearProgressIndicator(
                    value: _score / 100,
                    minHeight: 6,
                    backgroundColor: _scoreColor.withOpacity(.15),
                    valueColor: AlwaysStoppedAnimation(_scoreColor),
                  ),
                ),
              ]),
            ),
          ),
          const SizedBox(height: 16),

          // Checks
          if (p != null) ...[
            _section('Security Checks'),
            _check('Root / Jailbreak', !p.isRooted,
              p.isRooted ? 'Device is rooted — HIGH RISK' : 'Device is not rooted'),
            _check('Developer Mode', !p.developerModeOn,
              p.developerModeOn ? 'Developer options active — policy violation' : 'Developer options disabled'),
            _check('Disk Encryption', p.isEncrypted,
              p.isEncrypted ? 'Full-disk encryption enabled' : 'Encryption not confirmed'),
            _check('Screen Lock', p.hasPasscode ?? true,
              (p.hasPasscode ?? true) ? 'Screen lock configured' : 'No screen lock set'),
            const SizedBox(height: 16),

            _section('Device Information'),
            _info('OS Version',   p.osVersion),
            _info('Build',        p.buildVersion),
            if (p.osVersion.isNotEmpty) ...[
              const SizedBox(height: 16),
            ],
          ],

          // Sideloaded apps
          _section('Sideloaded Apps (${_sideloaded.length})'),
          if (_sideloaded.isEmpty)
            _check('App Sources', true, 'No sideloaded apps detected')
          else
            for (final app in _sideloaded)
              _check(app, false, 'Installed outside app store', icon: Icons.android),
          const SizedBox(height: 20),
        ],
      ),
    );
  }

  Widget _section(String label) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Text(label, style: TextStyle(
      fontSize: 11.5, fontWeight: FontWeight.w700, letterSpacing: 1.1,
      color: Theme.of(context).colorScheme.onSurfaceVariant)),
  );

  Widget _check(String label, bool ok, String detail, {IconData icon = Icons.check_circle}) {
    final color = ok ? const Color(0xFF22C55E) : const Color(0xFFEF4444);
    return Card(
      margin: const EdgeInsets.only(bottom: 6),
      child: ListTile(
        dense: true,
        leading: Icon(ok ? Icons.check_circle_outline : Icons.cancel_outlined, color: color, size: 22),
        title: Text(label, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
        subtitle: Text(detail, style: const TextStyle(fontSize: 11.5)),
        trailing: Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: color.withOpacity(.1),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(color: color.withOpacity(.3)),
          ),
          child: Text(ok ? 'PASS' : 'FAIL',
            style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800, color: color, letterSpacing: .8)),
        ),
      ),
    );
  }

  Widget _info(String label, String value) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(children: [
      Text(label, style: const TextStyle(fontSize: 12.5, color: Colors.grey)),
      const Spacer(),
      Text(value, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
    ]),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 3 — Activity
// ─────────────────────────────────────────────────────────────────────────────

class _ActivityTab extends StatefulWidget {
  const _ActivityTab();
  @override State<_ActivityTab> createState() => _ActivityTabState();
}

class _ActivityTabState extends State<_ActivityTab> {
  bool _loading = true;
  List _events  = [];

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final agentId = await SecureStore.agentId();
    List evts = [];
    if (agentId != null) {
      try {
        final c   = await ApiClient.fromStorage();
        final r   = await c.get('/api/agents/$agentId/activity');
        evts = (r['events'] ?? r['data'] ?? r['items'] ?? []) as List;
      } catch (_) {}
    }
    if (!mounted) return;
    setState(() { _loading = false; _events = evts; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    if (_events.isEmpty) {
      return Center(
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(Icons.history, size: 64, color: Colors.grey.shade400),
          const SizedBox(height: 12),
          const Text('No Activity Yet', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          Text('Events will appear after the first check-in.',
            style: TextStyle(color: Colors.grey.shade500, fontSize: 12)),
        ]),
      );
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.separated(
        padding: const EdgeInsets.all(16),
        itemCount: _events.length,
        separatorBuilder: (_, __) => const SizedBox(height: 1),
        itemBuilder: (_, i) {
          final e    = _events[i] as Map<String, dynamic>;
          final type = (e['event_type'] ?? e['type'] ?? 'event').toString();
          final ts   = e['created_at'] ?? e['timestamp'] ?? '';
          return Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: Theme.of(context).colorScheme.surfaceContainerLow,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: Theme.of(context).colorScheme.outlineVariant),
            ),
            child: Row(children: [
              Container(
                width: 32, height: 32,
                decoration: BoxDecoration(
                  color: _eventColor(type).withOpacity(.12),
                  shape: BoxShape.circle,
                ),
                child: Icon(_eventIcon(type), color: _eventColor(type), size: 16),
              ),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(_eventLabel(type),
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                if (e['description'] != null)
                  Text(e['description'].toString(),
                    style: const TextStyle(fontSize: 11.5, color: Colors.grey),
                    maxLines: 1, overflow: TextOverflow.ellipsis),
              ])),
              if (ts.isNotEmpty)
                Text(_fmtTs(ts),
                  style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            ]),
          );
        },
      ),
    );
  }

  IconData _eventIcon(String t) => switch (t) {
    'checkin'   || 'check_in'  => Icons.sync,
    'alert'     || 'threat'    => Icons.warning_amber,
    'command'   || 'task'      => Icons.terminal,
    'scan'                     => Icons.bug_report_outlined,
    'enrollment'               => Icons.phone_android,
    _                          => Icons.circle_outlined,
  };

  Color _eventColor(String t) => switch (t) {
    'alert' || 'threat'  => const Color(0xFFEF4444),
    'checkin' || 'check_in' => const Color(0xFF22C55E),
    'command' || 'task'  => const Color(0xFF3B82F6),
    _                    => Colors.grey,
  };

  String _eventLabel(String t) => switch (t) {
    'checkin' || 'check_in' => 'Check-in completed',
    'alert'    => 'Alert generated',
    'threat'   => 'Threat detected',
    'command'  => 'Command received',
    'task'     => 'Task executed',
    'scan'     => 'Vulnerability scan',
    'enrollment' => 'Device enrolled',
    _          => t.replaceAll('_', ' '),
  };

  String _fmtTs(String ts) {
    try {
      final dt  = DateTime.parse(ts).toLocal();
      final now = DateTime.now();
      final diff = now.difference(dt);
      if (diff.inMinutes < 1)  return 'just now';
      if (diff.inHours   < 1)  return '${diff.inMinutes}m ago';
      if (diff.inHours   < 24) return '${diff.inHours}h ago';
      return '${diff.inDays}d ago';
    } catch (_) { return ts; }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared Widgets
// ─────────────────────────────────────────────────────────────────────────────

class _StatChip extends StatelessWidget {
  final String value, label;
  final Color color;
  const _StatChip({required this.value, required this.label, required this.color});

  @override
  Widget build(BuildContext context) {
    return Expanded(child: Container(
      padding: const EdgeInsets.symmetric(vertical: 10),
      decoration: BoxDecoration(
        color: color.withOpacity(.08),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(.2)),
      ),
      child: Column(children: [
        Text(value, style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800, color: color)),
        const SizedBox(height: 2),
        Text(label, style: TextStyle(fontSize: 10.5, color: color.withOpacity(.8))),
      ]),
    ));
  }
}

class _StatusCard extends StatelessWidget {
  final IconData icon;
  final String title, value;
  final Color color;
  final VoidCallback? onTap;
  const _StatusCard({required this.icon, required this.title, required this.value, required this.color, this.onTap});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Material(
      color: cs.surfaceContainerLow,
      borderRadius: BorderRadius.circular(12),
      child: InkWell(
        borderRadius: BorderRadius.circular(12),
        onTap: onTap,
        child: Container(
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: cs.outlineVariant),
          ),
          child: Row(children: [
            Container(
              width: 36, height: 36,
              decoration: BoxDecoration(
                color: color.withOpacity(.1),
                borderRadius: BorderRadius.circular(9),
              ),
              child: Icon(icon, color: color, size: 18),
            ),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(title, style: const TextStyle(fontSize: 11, color: Colors.grey)),
              Text(value,
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600),
                overflow: TextOverflow.ellipsis),
            ])),
            Icon(Icons.circle, size: 8, color: color),
          ]),
        ),
      ),
    );
  }
}

class _ActionButton extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onTap;
  const _ActionButton({required this.icon, required this.label, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Expanded(child: InkWell(
      borderRadius: BorderRadius.circular(10),
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(vertical: 12),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          color: cs.surfaceContainerLow,
          border: Border.all(color: cs.outlineVariant),
        ),
        child: Column(children: [
          Icon(icon, size: 22, color: cs.primary),
          const SizedBox(height: 4),
          Text(label, style: TextStyle(fontSize: 10.5, color: cs.primary, fontWeight: FontWeight.w600),
            textAlign: TextAlign.center),
        ]),
      ),
    ));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Protection level enum
// ─────────────────────────────────────────────────────────────────────────────

enum _StatusLevel {
  protected(
    label: 'PROTECTED',
    color: Color(0xFF22C55E),
    icon: Icons.verified_user,
    progress: 1.0,
  ),
  monitoring(
    label: 'MONITORING',
    color: Color(0xFF3B82F6),
    icon: Icons.shield_outlined,
    progress: 0.7,
  ),
  warning(
    label: 'WARNING',
    color: Color(0xFFF59E0B),
    icon: Icons.warning_amber,
    progress: 0.55,
  ),
  alert(
    label: 'ALERT',
    color: Color(0xFFF97316),
    icon: Icons.crisis_alert,
    progress: 0.4,
  ),
  compromised(
    label: 'COMPROMISED',
    color: Color(0xFFEF4444),
    icon: Icons.gpp_bad,
    progress: 0.2,
  );

  final String label;
  final Color color;
  final IconData icon;
  final double progress;
  const _StatusLevel({required this.label, required this.color, required this.icon, required this.progress});
}
