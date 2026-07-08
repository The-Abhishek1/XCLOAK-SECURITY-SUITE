import 'dart:io';
import 'dart:math';

import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:flutter/material.dart';
import 'package:package_info_plus/package_info_plus.dart';

import '../models/device_posture.dart';
import '../services/api_client.dart';
import '../services/enrollment_service.dart';
import '../services/posture_collector.dart';
import '../services/secure_storage.dart';
import '../services/threat_detector.dart';
import 'mode_select.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const _kGreen  = Color(0xFF22C55E);
const _kBlue   = Color(0xFF3B82F6);
const _kAmber  = Color(0xFFF59E0B);
const _kOrange = Color(0xFFF97316);
const _kRed    = Color(0xFFEF4444);
const _kPurple = Color(0xFF8B5CF6);

// ─────────────────────────────────────────────────────────────────────────────
// Protection level enum
// ─────────────────────────────────────────────────────────────────────────────

enum _ProtLevel {
  protected(label: 'PROTECTED',     color: _kGreen,  icon: Icons.verified_user,  arc: 1.00),
  monitoring(label: 'MONITORING',   color: _kBlue,   icon: Icons.shield_outlined, arc: 0.72),
  warning(label: 'WARNING',         color: _kAmber,  icon: Icons.warning_amber,   arc: 0.55),
  alert(label: 'ALERT',             color: _kOrange, icon: Icons.crisis_alert,    arc: 0.38),
  compromised(label: 'COMPROMISED', color: _kRed,    icon: Icons.gpp_bad,         arc: 0.20);

  final String   label;
  final Color    color;
  final IconData icon;
  final double   arc;
  const _ProtLevel({required this.label, required this.color,
    required this.icon, required this.arc});
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert severity
// ─────────────────────────────────────────────────────────────────────────────

enum _Sev { critical, high, medium, low, info }

extension _SevExt on _Sev {
  Color  get color => switch (this) {
    _Sev.critical => _kRed,
    _Sev.high     => _kOrange,
    _Sev.medium   => _kAmber,
    _Sev.low      => _kBlue,
    _Sev.info     => Colors.grey,
  };
  String get label => name.toUpperCase();
}

_Sev _parseSev(dynamic raw) {
  final s = (raw ?? '').toString().toLowerCase();
  if (s.contains('critical')) return _Sev.critical;
  if (s.contains('high'))     return _Sev.high;
  if (s.contains('medium'))   return _Sev.medium;
  if (s.contains('low'))      return _Sev.low;
  return _Sev.info;
}

String _timeAgo(String ts) {
  try {
    final diff = DateTime.now().difference(DateTime.parse(ts).toLocal());
    if (diff.inSeconds < 60)  return '${diff.inSeconds}s ago';
    if (diff.inMinutes < 60)  return '${diff.inMinutes}m ago';
    if (diff.inHours   < 24)  return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  } catch (_) { return ts; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shell scaffold
// ─────────────────────────────────────────────────────────────────────────────

class AgentShell extends StatefulWidget {
  const AgentShell({super.key});
  @override
  State<AgentShell> createState() => _AgentShellState();
}

class _AgentShellState extends State<AgentShell> {
  int _tab = 0;

  static const _pages = <Widget>[
    _OverviewTab(),
    _ThreatsTab(),
    _PostureTab(),
    _NetworkTab(),
    _TasksTab(),
  ];

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Scaffold(
      appBar: AppBar(
        backgroundColor: cs.surface,
        surfaceTintColor: Colors.transparent,
        title: Row(children: [
          Container(
            width: 30, height: 30,
            decoration: BoxDecoration(
              gradient: const LinearGradient(colors: [Color(0xFF1565C0), Color(0xFF0288D1)]),
              borderRadius: BorderRadius.circular(8),
            ),
            child: const Icon(Icons.security, color: Colors.white, size: 16),
          ),
          const SizedBox(width: 10),
          const Text('XCloak Agent',
            style: TextStyle(fontSize: 16, fontWeight: FontWeight.w700, letterSpacing: -.2)),
        ]),
        actions: [
          IconButton(
            icon: const Icon(Icons.grid_view_rounded),
            tooltip: 'Mode Selection',
            onPressed: () => Navigator.pushReplacement(context,
              MaterialPageRoute(builder: (_) => const ModeSelectScreen())),
          ),
          PopupMenuButton<String>(
            icon: const Icon(Icons.more_vert),
            onSelected: (v) async {
              if (v == 'unenroll') {
                final confirm = await showDialog<bool>(
                  context: context,
                  builder: (_) => AlertDialog(
                    title: const Text('Unenroll Device'),
                    content: const Text(
                      'This will remove the device from XCloak and stop all monitoring. Continue?'),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
                      FilledButton(
                        style: FilledButton.styleFrom(backgroundColor: Colors.red),
                        onPressed: () => Navigator.pop(context, true),
                        child: const Text('Unenroll'),
                      ),
                    ],
                  ),
                );
                if (confirm == true && context.mounted) {
                  await EnrollmentService.unenroll();
                  if (context.mounted) {
                    Navigator.pushAndRemoveUntil(
                      context,
                      MaterialPageRoute(builder: (_) => const ModeSelectScreen()),
                      (_) => false,
                    );
                  }
                }
              }
            },
            itemBuilder: (_) => const [
              PopupMenuItem(value: 'unenroll',
                child: Row(children: [
                  Icon(Icons.link_off, size: 18, color: Colors.red),
                  SizedBox(width: 10),
                  Text('Unenroll Device', style: TextStyle(color: Colors.red)),
                ])),
            ],
          ),
        ],
      ),
      body: IndexedStack(index: _tab, children: _pages),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _tab,
        onDestinationSelected: (i) => setState(() => _tab = i),
        destinations: const [
          NavigationDestination(
            icon: Icon(Icons.shield_outlined),
            selectedIcon: Icon(Icons.shield),
            label: 'Overview'),
          NavigationDestination(
            icon: Icon(Icons.warning_amber_rounded),
            selectedIcon: Icon(Icons.warning_rounded),
            label: 'Threats'),
          NavigationDestination(
            icon: Icon(Icons.health_and_safety_outlined),
            selectedIcon: Icon(Icons.health_and_safety),
            label: 'Posture'),
          NavigationDestination(
            icon: Icon(Icons.wifi_outlined),
            selectedIcon: Icon(Icons.wifi),
            label: 'Network'),
          NavigationDestination(
            icon: Icon(Icons.task_alt_outlined),
            selectedIcon: Icon(Icons.task_alt),
            label: 'Tasks'),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 0 — Overview
// ─────────────────────────────────────────────────────────────────────────────

class _OverviewTab extends StatefulWidget {
  const _OverviewTab();
  @override
  State<_OverviewTab> createState() => _OverviewTabState();
}

class _OverviewTabState extends State<_OverviewTab>
    with AutomaticKeepAliveClientMixin, SingleTickerProviderStateMixin {
  @override
  bool get wantKeepAlive => true;

  late final AnimationController _ringCtrl;
  late Animation<double>         _ringAnim;

  bool   _loading = true;
  Map<String, dynamic> _summary = {};
  List   _alerts    = [];
  List   _sideloaded = [];
  DevicePosture? _posture;
  int    _taskCount  = 0;
  String? _agentVersion;
  String? _serverVersion;
  bool   _updateAvail   = false;
  int?   _agentId;
  int?   _pingMs;
  bool   _serverOnline  = false;

  @override
  void initState() {
    super.initState();
    _ringCtrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 1200));
    _ringAnim = Tween(begin: 0.0, end: 0.0)
        .animate(CurvedAnimation(parent: _ringCtrl, curve: Curves.easeOutCubic));
    _load();
    _checkPendingMessage();
  }

  // Show any server-pushed message (e.g. from the 'message' MDM command)
  // and clear it so it doesn't show again.
  Future<void> _checkPendingMessage() async {
    final msg = await SecureStore.pendingMessage();
    if (msg == null || msg.isEmpty) return;
    await SecureStore.clearPendingMessage();
    if (!mounted) return;
    showDialog<void>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Message from Admin'),
        content: Text(msg),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context), child: const Text('OK')),
        ],
      ),
    );
  }

  @override
  void dispose() { _ringCtrl.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final c    = await ApiClient.fromStorage();
    final id   = await SecureStore.agentId();
    final info = await PackageInfo.fromPlatform();
    _agentVersion = info.version;
    _agentId = id;

    await Future.wait([
      _fetchSummary(c), _fetchAlerts(c), _fetchTasks(c),
      _fetchSideloaded(), _fetchPosture(), _checkRelease(c), _ping(c),
    ]);

    if (!mounted) return;
    final target = _level.arc;
    _ringAnim = Tween(begin: _ringAnim.value, end: target)
        .animate(CurvedAnimation(parent: _ringCtrl, curve: Curves.easeOutCubic));
    _ringCtrl.forward(from: 0);
    setState(() => _loading = false);
  }

  Future<void> _fetchSummary(ApiClient c) async {
    try {
      _summary = await c.get('/api/agents/self/summary');
    } on ApiException catch (e) {
      if (e.statusCode == 403 || e.statusCode == 401) _handleUnenrolled();
    } catch (_) {}
  }

  // Called when the server rejects a request because the device was unenrolled.
  void _handleUnenrolled() {
    EnrollmentService.unenroll().then((_) {
      if (!mounted) return;
      Navigator.pushAndRemoveUntil(
        context,
        MaterialPageRoute(builder: (_) => const ModeSelectScreen()),
        (_) => false,
      );
    });
  }

  Future<void> _fetchAlerts(ApiClient c) async {
    try {
      final r = await c.get('/api/agents/self/alerts');
      _alerts = (r['alerts'] ?? []) as List;
    } catch (_) {}
  }

  Future<void> _fetchTasks(ApiClient c) async {
    try {
      final r = await c.get('/api/agents/self/tasks');
      _taskCount = (r['count'] ?? 0) as int;
    } catch (_) {}
  }

  Future<void> _fetchSideloaded() async {
    _sideloaded = await ThreatDetector.sideloadedPackages();
  }

  Future<void> _fetchPosture() async {
    _posture = await PostureCollector.collect();
  }

  Future<void> _checkRelease(ApiClient c) async {
    try {
      final r = await c.get('/api/agent-releases/android');
      _serverVersion = r['version']?.toString();
      if (_serverVersion != null && _agentVersion != null) {
        _updateAvail = _serverVersion != _agentVersion;
      }
    } catch (_) {}
  }

  Future<void> _ping(ApiClient c) async {
    try {
      final sw = Stopwatch()..start();
      await c.get('/api/agents/self/summary');
      sw.stop();
      _pingMs = sw.elapsedMilliseconds;
      _serverOnline = true;
    } catch (_) {
      _serverOnline = false;
      _pingMs = null;
    }
  }

  _ProtLevel get _level {
    if (_posture?.isRooted == true)                          return _ProtLevel.compromised;
    if (_criticalCount > 0)                                  return _ProtLevel.alert;
    if (_alerts.isNotEmpty || _sideloaded.isNotEmpty)        return _ProtLevel.warning;
    if (!_serverOnline)                                      return _ProtLevel.monitoring;
    return _ProtLevel.protected;
  }

  int get _criticalCount => _alerts.where((a) {
    final s = _parseSev(a['severity'] ?? a['level'] ?? '');
    return s == _Sev.critical || s == _Sev.high;
  }).length;

  int get _postureScore {
    if (_posture == null) return 100;
    int s = 100;
    if (_posture!.isRooted)              s -= 40;
    if (_posture!.developerModeOn)       s -= 15;
    if (_posture!.usbDebuggingEnabled)   s -= 10;
    if (_posture!.unknownSourcesEnabled) s -= 10;
    s -= (_sideloaded.length * 8).clamp(0, 30);
    return s.clamp(0, 100);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    final cs = Theme.of(context).colorScheme;
    final lv = _level;

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.only(bottom: 24),
        children: [

          // ── Gradient header with protection ring ───────────────────────
          Container(
            decoration: BoxDecoration(
              gradient: LinearGradient(
                begin: Alignment.topLeft, end: Alignment.bottomRight,
                colors: [lv.color.withValues(alpha: .09), cs.surface],
              ),
            ),
            padding: const EdgeInsets.fromLTRB(20, 28, 20, 22),
            child: Column(children: [
              SizedBox(
                width: 168, height: 168,
                child: AnimatedBuilder(
                  animation: _ringAnim,
                  builder: (_, __) => CustomPaint(
                    painter: _RingPainter(
                      progress: _loading ? 0 : _ringAnim.value,
                      color: lv.color, strokeWidth: 11),
                    child: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
                      Icon(lv.icon, color: lv.color, size: 34),
                      const SizedBox(height: 6),
                      Text(lv.label, style: TextStyle(
                        fontSize: 11, fontWeight: FontWeight.w900,
                        color: lv.color, letterSpacing: 1.6)),
                    ])),
                  ),
                ),
              ),
              const SizedBox(height: 16),
              // Server status pill
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 6),
                decoration: BoxDecoration(
                  color: (_serverOnline ? _kGreen : _kRed).withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(
                    color: (_serverOnline ? _kGreen : _kRed).withValues(alpha: .3)),
                ),
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  Container(
                    width: 7, height: 7,
                    decoration: BoxDecoration(
                      color: _serverOnline ? _kGreen : _kRed,
                      shape: BoxShape.circle),
                  ),
                  const SizedBox(width: 7),
                  Text(
                    _serverOnline
                      ? 'Server online${_pingMs != null ? " · ${_pingMs}ms" : ""}'
                      : 'Server unreachable',
                    style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700,
                      color: _serverOnline ? _kGreen : _kRed)),
                ]),
              ),
            ]),
          ),

          // ── Update banner ──────────────────────────────────────────────
          if (_updateAvail)
            Padding(
              padding: const EdgeInsets.fromLTRB(16, 0, 16, 0),
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  gradient: LinearGradient(colors: [
                    _kPurple.withValues(alpha: .12),
                    _kBlue.withValues(alpha: .06),
                  ]),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: _kPurple.withValues(alpha: .3)),
                ),
                child: Row(children: [
                  const Icon(Icons.system_update_alt, color: _kPurple, size: 18),
                  const SizedBox(width: 10),
                  Expanded(child: Text('Update available — v$_serverVersion',
                    style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600,
                      color: _kPurple))),
                ]),
              ),
            ),

          const SizedBox(height: 16),

          // ── Stats row ──────────────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16),
            child: Row(children: [
              _StatChip(
                value: _loading ? '–' : '${_alerts.length}',
                label: 'Threats',
                color: _alerts.isEmpty ? _kGreen : _kRed),
              const SizedBox(width: 8),
              _StatChip(
                value: _loading ? '–' : '$_postureScore',
                label: 'Score',
                color: _postureScore >= 80 ? _kGreen : _postureScore >= 60 ? _kAmber : _kRed),
              const SizedBox(width: 8),
              _StatChip(
                value: _loading ? '–' : '$_taskCount',
                label: 'Tasks',
                color: _taskCount > 0 ? _kAmber : _kBlue),
              const SizedBox(width: 8),
              _StatChip(
                value: _loading ? '–' : '${_sideloaded.length}',
                label: 'Sideloaded',
                color: _sideloaded.isEmpty ? _kGreen : _kOrange),
            ]),
          ),
          const SizedBox(height: 16),

          // ── Agent identity card ────────────────────────────────────────
          _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            _SectionLabel('Agent Identity'),
            const SizedBox(height: 10),
            _InfoRow(label: 'Agent ID',  value: _agentId != null ? '#$_agentId' : '–'),
            _InfoRow(label: 'Version',   value: _agentVersion ?? '–'),
            _InfoRow(label: 'Status',
              value: _summary['status']?.toString() ?? (_serverOnline ? 'Online' : 'Offline')),
            _InfoRow(label: 'Last Seen', value: _fmtTs(_summary['last_seen']?.toString())),
            _InfoRow(label: 'Platform',  value: Platform.isAndroid ? 'Android' : 'iOS'),
            if (_posture != null) ...[
              _InfoRow(label: 'OS',      value: _posture!.osVersion),
              if (_posture!.manufacturer.isNotEmpty)
                _InfoRow(label: 'Device', value: '${_posture!.manufacturer} (${_posture!.hardware})'),
            ],
          ])),
          const SizedBox(height: 12),

          // ── Device status card ─────────────────────────────────────────
          if (_posture != null)
            _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const _SectionLabel('Device Status'),
              const SizedBox(height: 10),
              // Battery
              _ProgressRow(
                icon: _posture!.batteryCharging ? Icons.battery_charging_full : Icons.battery_std,
                iconColor: _posture!.batteryLevel < 15 ? _kRed
                  : _posture!.batteryLevel < 30 ? _kAmber : _kGreen,
                label: _posture!.batteryLevel >= 0
                  ? 'Battery ${_posture!.batteryLevel}%${_posture!.batteryCharging ? " ⚡" : ""}'
                  : 'Battery',
                value: _posture!.batteryLevel.clamp(0, 100) / 100,
                color: _posture!.batteryLevel < 15 ? _kRed
                  : _posture!.batteryLevel < 30 ? _kAmber : _kGreen,
              ),
              const SizedBox(height: 8),
              // Storage
              if (_posture!.storageTotalGb > 0)
                _ProgressRow(
                  icon: Icons.storage_rounded,
                  iconColor: _kBlue,
                  label: 'Storage — '
                    '${_posture!.storageFreeGb.toStringAsFixed(1)} GB free of '
                    '${_posture!.storageTotalGb.toStringAsFixed(1)} GB',
                  value: 1 - (_posture!.storageFreeGb / _posture!.storageTotalGb)
                             .clamp(0.0, 1.0),
                  color: _posture!.storageFreeGb < 1 ? _kRed
                    : _posture!.storageFreeGb < 3 ? _kAmber : _kBlue,
                ),
              const SizedBox(height: 8),
              // Network
              Row(children: [
                Icon(
                  _posture!.networkType == 'wifi' ? Icons.wifi
                    : _posture!.networkType == 'mobile' ? Icons.signal_cellular_alt
                    : Icons.signal_wifi_off,
                  size: 16,
                  color: _posture!.networkType == 'none' ? _kRed : _kBlue),
                const SizedBox(width: 8),
                Expanded(child: Text(
                  _posture!.networkType == 'wifi'
                    ? 'Wi-Fi${_posture!.wifiSsid.isNotEmpty ? " (${_posture!.wifiSsid})" : ""}'
                    : _posture!.networkType == 'mobile' ? 'Mobile data'
                    : _posture!.networkType == 'none' ? 'Offline' : _posture!.networkType,
                  style: const TextStyle(fontSize: 12.5))),
                if (_posture!.vpnActive)
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                    decoration: BoxDecoration(
                      color: _kGreen.withValues(alpha: .12),
                      borderRadius: BorderRadius.circular(5)),
                    child: const Text('VPN',
                      style: TextStyle(fontSize: 10.5, color: _kGreen,
                        fontWeight: FontWeight.w700))),
              ]),
            ])),
          const SizedBox(height: 12),

          // ── Latest alert preview ───────────────────────────────────────
          if (_alerts.isNotEmpty) ...[
            _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                const _SectionLabel('Latest Alert'),
                const Spacer(),
                Text('${_alerts.length} total',
                  style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ]),
              const SizedBox(height: 10),
              _AlertCard(alert: _alerts.first as Map<String, dynamic>, compact: true),
            ])),
            const SizedBox(height: 12),
          ],

          // ── Quick actions ──────────────────────────────────────────────
          _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const _SectionLabel('Quick Actions'),
            const SizedBox(height: 10),
            Row(children: [
              _ActionTile(
                icon: Icons.sync_rounded, label: 'Force\nSync', color: _kBlue,
                onTap: () async {
                  try {
                    final c = await ApiClient.fromStorage();
                    await c.post('/api/agents/heartbeat', {});
                    if (!mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                      content: Text('Check-in sent'), backgroundColor: _kGreen));
                    _load();
                  } catch (_) {
                    if (!mounted) return;
                    ScaffoldMessenger.of(context).showSnackBar(const SnackBar(
                      content: Text('Check-in failed'), backgroundColor: _kRed));
                  }
                },
              ),
              const SizedBox(width: 8),
              _ActionTile(
                icon: Icons.bug_report_outlined, label: 'Scan\nThreats', color: _kOrange,
                onTap: () async {
                  final apps = await ThreatDetector.sideloadedPackages();
                  if (!mounted) return;
                  ScaffoldMessenger.of(context).showSnackBar(SnackBar(
                    content: Text(apps.isEmpty
                      ? 'No threats detected' : '${apps.length} sideloaded app(s) found'),
                    backgroundColor: apps.isEmpty ? _kGreen : _kAmber));
                  _load();
                },
              ),
              const SizedBox(width: 8),
              _ActionTile(
                icon: Icons.refresh_rounded, label: 'Refresh\nAll', color: _kGreen,
                onTap: _load),
              const SizedBox(width: 8),
              _ActionTile(
                icon: Icons.grid_view_rounded, label: 'Mode\nSelect', color: _kPurple,
                onTap: () => Navigator.pushReplacement(context,
                  MaterialPageRoute(builder: (_) => const ModeSelectScreen()))),
            ]),
          ])),
        ],
      ),
    );
  }

  String _fmtTs(String? ts) {
    if (ts == null || ts.isEmpty) return '–';
    return _timeAgo(ts);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 1 — Threats
// ─────────────────────────────────────────────────────────────────────────────

class _ThreatsTab extends StatefulWidget {
  const _ThreatsTab();
  @override
  State<_ThreatsTab> createState() => _ThreatsTabState();
}

class _ThreatsTabState extends State<_ThreatsTab> {
  bool  _loading    = true;
  List  _alerts     = [];
  List  _sideloaded = [];
  _Sev? _filter;
  bool  _sideExpanded = true;
  final Set<int> _expanded = {};

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    List sa = [], sl = [];
    try {
      final r = await (await ApiClient.fromStorage()).get('/api/agents/self/alerts');
      sa = (r['alerts'] ?? []) as List;
    } catch (_) {}
    sl = await ThreatDetector.sideloadedPackages();
    if (!mounted) return;
    setState(() { _loading = false; _alerts = sa; _sideloaded = sl; });
  }

  List get _filtered => _filter == null
    ? _alerts
    : _alerts.where((a) => _parseSev(a['severity'] ?? a['level']) == _filter).toList();

  int _count(_Sev s) =>
    _alerts.where((a) => _parseSev(a['severity'] ?? a['level']) == s).length;

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    final cs       = Theme.of(context).colorScheme;
    final filtered = _filtered;

    if (_alerts.isEmpty && _sideloaded.isEmpty) {
      return Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
        Icon(Icons.verified_user_outlined, size: 72, color: _kGreen.withValues(alpha: .5)),
        const SizedBox(height: 16),
        const Text('No Threats Detected',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w700)),
        const SizedBox(height: 6),
        Text('Your device is clean.', style: TextStyle(color: cs.onSurface.withValues(alpha: .5))),
        const SizedBox(height: 24),
        TextButton.icon(onPressed: _load, icon: const Icon(Icons.refresh),
          label: const Text('Refresh')),
      ]));
    }

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Filter bar
          SingleChildScrollView(
            scrollDirection: Axis.horizontal,
            child: Row(children: [
              _FilterChip(label: 'All', count: _alerts.length,
                selected: _filter == null, color: Colors.grey,
                onTap: () => setState(() => _filter = null)),
              ..._Sev.values.map((s) => Padding(
                padding: const EdgeInsets.only(left: 6),
                child: _FilterChip(label: s.label, count: _count(s),
                  selected: _filter == s, color: s.color,
                  onTap: () => setState(() => _filter = _filter == s ? null : s)),
              )),
            ]),
          ),
          const SizedBox(height: 14),

          // Alert list
          if (filtered.isNotEmpty) ...[
            Text('${filtered.length} alert${filtered.length == 1 ? "" : "s"}',
              style: TextStyle(fontSize: 11.5, color: cs.onSurface.withValues(alpha: .5),
                fontWeight: FontWeight.w600)),
            const SizedBox(height: 8),
            ...List.generate(filtered.length, (i) {
              final a = filtered[i] as Map<String, dynamic>;
              final exp = _expanded.contains(i);
              return Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: _AlertCard(
                  alert: a, expanded: exp,
                  onTap: () => setState(() => exp ? _expanded.remove(i) : _expanded.add(i)),
                ),
              );
            }),
          ] else if (_filter != null)
            Center(child: Padding(
              padding: const EdgeInsets.symmetric(vertical: 32),
              child: Text('No ${_filter!.label} alerts',
                style: TextStyle(color: cs.onSurface.withValues(alpha: .4))),
            )),

          // Sideloaded apps
          if (_sideloaded.isNotEmpty) ...[
            const SizedBox(height: 8),
            GestureDetector(
              onTap: () => setState(() => _sideExpanded = !_sideExpanded),
              child: Row(children: [
                Container(width: 3, height: 16,
                  decoration: BoxDecoration(color: _kOrange,
                    borderRadius: BorderRadius.circular(2))),
                const SizedBox(width: 8),
                Text('Sideloaded Apps (${_sideloaded.length})',
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
                const Spacer(),
                Icon(_sideExpanded ? Icons.expand_less : Icons.expand_more,
                  size: 18, color: Colors.grey),
              ]),
            ),
            if (_sideExpanded) ...[
              const SizedBox(height: 8),
              ..._sideloaded.map((pkg) => Container(
                margin: const EdgeInsets.only(bottom: 6),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: _kOrange.withValues(alpha: .05),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: _kOrange.withValues(alpha: .2))),
                child: Row(children: [
                  const Icon(Icons.android, color: _kOrange, size: 18),
                  const SizedBox(width: 10),
                  Expanded(child: Text(pkg.toString(),
                    style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w500))),
                  _Pill(label: 'RISK', color: _kOrange),
                ]),
              )),
            ],
          ],
          const SizedBox(height: 12),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 2 — Posture
// ─────────────────────────────────────────────────────────────────────────────

class _PostureTab extends StatefulWidget {
  const _PostureTab();
  @override
  State<_PostureTab> createState() => _PostureTabState();
}

class _PostureTabState extends State<_PostureTab>
    with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  late Animation<double>         _anim;

  bool _loading     = true;
  bool _devExpanded = false;
  DevicePosture?     _posture;
  List<String>       _sideloaded = [];
  AndroidDeviceInfo? _devInfo;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 1400));
    _anim = Tween(begin: 0.0, end: 0.0)
        .animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeOutCubic));
    _load();
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final p  = await PostureCollector.collect();
    final sl = await ThreatDetector.sideloadedPackages();
    AndroidDeviceInfo? di;
    try { di = await DeviceInfoPlugin().androidInfo; } catch (_) {}
    if (!mounted) return;
    setState(() { _posture = p; _sideloaded = sl; _devInfo = di; _loading = false; });
    _anim = Tween(begin: 0.0, end: _score / 100)
        .animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeOutCubic));
    _ctrl.forward(from: 0);
  }

  int get _score {
    if (_posture == null) return 100;
    int s = 100;
    if (_posture!.isRooted)                      s -= 40;
    if (_posture!.developerModeOn)               s -= 15;
    if (_posture!.usbDebuggingEnabled)           s -= 10;
    if (_posture!.unknownSourcesEnabled)         s -= 10;
    if (!(_posture!.isEncrypted ?? true))        s -= 15;
    if (!(_posture!.hasPasscode  ?? true))       s -= 10;
    final batt = _posture!.batteryLevel;
    if (batt >= 0 && batt < 10)                 s -= 5;
    s -= (_sideloaded.length * 8).clamp(0, 25);
    return s.clamp(0, 100);
  }

  Color  get _scoreColor  => _score >= 85 ? _kGreen : _score >= 65 ? _kAmber : _kRed;
  String get _scoreLabel  => _score >= 85 ? 'Excellent' : _score >= 65 ? 'Fair'
      : _score >= 40 ? 'At Risk' : 'Critical';

  int get _deviceScore {
    int s = 100;
    if (_posture?.isRooted == true)             s -= 60;
    if (_posture?.developerModeOn == true)      s -= 20;
    if (_posture?.usbDebuggingEnabled == true)  s -= 10;
    if (_posture?.unknownSourcesEnabled == true) s -= 10;
    return s.clamp(0, 100);
  }

  int get _dataScore {
    int s = 100;
    if (!(_posture?.isEncrypted ?? true)) s -= 50;
    if (!(_posture?.hasPasscode  ?? true)) s -= 40;
    return s.clamp(0, 100);
  }

  int get _appScore => (100 - (_sideloaded.length * 15).clamp(0, 100)).clamp(0, 100);

  int get _hardwareScore {
    final p = _posture;
    if (p == null) return 100;
    int s = 100;
    if (p.batteryLevel >= 0 && p.batteryLevel < 10) s -= 20;
    if (p.storageFreeGb > 0 && p.storageFreeGb < 1) s -= 15;
    return s.clamp(0, 100);
  }

  List<String> get _recommendations {
    final r = <String>[];
    if (_posture?.isRooted == true)
      r.add('Remove root access — device integrity compromised');
    if (_posture?.developerModeOn == true)
      r.add('Disable Developer Options in Settings → System');
    if (_posture?.usbDebuggingEnabled == true)
      r.add('Disable USB Debugging in Developer Options');
    if (_posture?.unknownSourcesEnabled == true)
      r.add('Disable "Install Unknown Apps" in Settings → Apps');
    if (!(_posture?.isEncrypted ?? true))
      r.add('Enable full-disk encryption in Security settings');
    if (!(_posture?.hasPasscode  ?? true))
      r.add('Set a screen lock PIN, pattern, or biometric');
    final batt = _posture?.batteryLevel ?? -1;
    if (batt >= 0 && batt < 15)
      r.add('Battery critically low (${batt}%) — charge device to maintain monitoring');
    if ((_posture?.storageFreeGb ?? 1) < 1)
      r.add('Storage nearly full — free space to ensure agent can write logs');
    if (_sideloaded.isNotEmpty)
      r.add('Uninstall ${_sideloaded.length} sideloaded app(s) from unknown sources');
    return r;
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());
    final p = _posture;

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Score ring card
          Card(child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(children: [
              Row(children: [
                SizedBox(
                  width: 100, height: 100,
                  child: AnimatedBuilder(
                    animation: _anim,
                    builder: (_, __) => CustomPaint(
                      painter: _RingPainter(progress: _anim.value, color: _scoreColor, strokeWidth: 9),
                      child: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
                        Text('$_score',
                          style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900,
                            color: _scoreColor)),
                        Text('/100', style: TextStyle(fontSize: 10, color: Colors.grey.shade500)),
                      ])),
                    ),
                  ),
                ),
                const SizedBox(width: 20),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  const Text('POSTURE SCORE',
                    style: TextStyle(fontSize: 10.5, letterSpacing: 1.2, color: Colors.grey,
                      fontWeight: FontWeight.w700)),
                  const SizedBox(height: 4),
                  Text(_scoreLabel,
                    style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: _scoreColor)),
                  const SizedBox(height: 10),
                  ClipRRect(
                    borderRadius: BorderRadius.circular(4),
                    child: LinearProgressIndicator(
                      value: _score / 100, minHeight: 5,
                      backgroundColor: _scoreColor.withValues(alpha: .15),
                      valueColor: AlwaysStoppedAnimation(_scoreColor),
                    ),
                  ),
                ])),
              ]),
              const SizedBox(height: 20),
              // Sub-scores row
              Row(children: [
                _SubScore(label: 'Device',   score: _deviceScore),
                _SubScore(label: 'Data',     score: _dataScore),
                _SubScore(label: 'Apps',     score: _appScore),
                _SubScore(label: 'Hardware', score: _hardwareScore),
              ]),
            ]),
          )),
          const SizedBox(height: 16),

          if (p != null) ...[
            // Device Integrity
            _GroupHeader(label: 'Device Integrity', score: _deviceScore),
            _CheckRow(label: 'Root / Jailbreak', pass: !p.isRooted,
              detail: p.isRooted
                ? 'Device is rooted — data isolation broken'
                : 'Device has not been rooted'),
            _CheckRow(label: 'Developer Mode', pass: !p.developerModeOn,
              detail: p.developerModeOn
                ? 'Developer options enabled — ADB access possible'
                : 'Developer options are disabled'),
            _CheckRow(label: 'USB Debugging', pass: !p.usbDebuggingEnabled,
              detail: p.usbDebuggingEnabled
                ? 'USB debugging on — ADB commands accepted when connected'
                : 'USB debugging is disabled'),
            _CheckRow(label: 'Unknown Sources', pass: !p.unknownSourcesEnabled,
              detail: p.unknownSourcesEnabled
                ? 'Install from unknown sources enabled — sideload risk elevated'
                : 'Unknown app installation is blocked'),
            const SizedBox(height: 16),

            // Data Protection
            _GroupHeader(label: 'Data Protection', score: _dataScore),
            _CheckRow(label: 'Disk Encryption', pass: p.isEncrypted ?? true,
              detail: (p.isEncrypted ?? true)
                ? 'Full-disk encryption is active'
                : 'Disk encryption not confirmed'),
            _CheckRow(label: 'Screen Lock', pass: p.hasPasscode ?? true,
              detail: (p.hasPasscode ?? true)
                ? 'Screen lock is configured'
                : 'No screen lock — unauthorized access risk'),
            const SizedBox(height: 16),

            // Hardware & Environment
            _GroupHeader(label: 'Hardware & Environment', score: _hardwareScore),
            _CheckRow(
              label: 'Battery',
              pass: p.batteryLevel < 0 || p.batteryLevel >= 15,
              detail: p.batteryLevel >= 0
                ? '${p.batteryLevel}% — ${p.batteryCharging ? "charging" : "on battery"}'
                : 'Battery level unavailable'),
            _CheckRow(
              label: 'Storage',
              pass: p.storageFreeGb <= 0 || p.storageFreeGb >= 1,
              detail: p.storageTotalGb > 0
                ? '${p.storageFreeGb.toStringAsFixed(1)} GB free of ${p.storageTotalGb.toStringAsFixed(1)} GB'
                : 'Storage stats unavailable'),
            _CheckRow(
              label: 'Network',
              pass: p.networkType != 'none',
              detail: p.networkType == 'wifi'
                ? 'Wi-Fi${p.wifiSsid.isNotEmpty ? " (${p.wifiSsid})" : ""}'
                : p.networkType == 'mobile'
                  ? 'Mobile data'
                  : p.networkType == 'none' ? 'Offline' : p.networkType),
            _CheckRow(
              label: 'VPN',
              pass: p.vpnActive,
              detail: p.vpnActive
                ? 'VPN tunnel active — traffic is protected'
                : 'No VPN — network traffic may be unencrypted'),
            const SizedBox(height: 16),

            // App Security
            _GroupHeader(label: 'App Security', score: _appScore),
            _CheckRow(label: 'Sideloaded Apps', pass: _sideloaded.isEmpty,
              detail: _sideloaded.isEmpty
                ? 'No apps installed outside official store'
                : '${_sideloaded.length} app(s) from unknown sources'),
            if (_sideloaded.isNotEmpty)
              ..._sideloaded.map((pkg) => Container(
                margin: const EdgeInsets.only(bottom: 4, left: 16),
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                decoration: BoxDecoration(
                  color: _kRed.withValues(alpha: .05),
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: _kRed.withValues(alpha: .15))),
                child: Row(children: [
                  const Icon(Icons.android, size: 14, color: _kRed),
                  const SizedBox(width: 8),
                  Expanded(child: Text(pkg,
                    style: const TextStyle(fontSize: 11.5, fontWeight: FontWeight.w500))),
                ]),
              )),
            const SizedBox(height: 16),

            // Recommendations
            if (_recommendations.isNotEmpty) ...[
              _GroupHeader(label: 'Recommendations', score: null),
              ..._recommendations.asMap().entries.map((e) => Container(
                margin: const EdgeInsets.only(bottom: 6),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
                decoration: BoxDecoration(
                  color: _kAmber.withValues(alpha: .06),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: _kAmber.withValues(alpha: .25))),
                child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Container(
                    width: 20, height: 20, alignment: Alignment.center,
                    decoration: BoxDecoration(
                      color: _kAmber.withValues(alpha: .15),
                      borderRadius: BorderRadius.circular(5)),
                    child: Text('${e.key + 1}',
                      style: const TextStyle(fontSize: 10.5, fontWeight: FontWeight.w800,
                        color: _kAmber)),
                  ),
                  const SizedBox(width: 10),
                  Expanded(child: Text(e.value, style: const TextStyle(fontSize: 12.5))),
                ]),
              )),
              const SizedBox(height: 16),
            ],

            // Device info accordion
            GestureDetector(
              onTap: () => setState(() => _devExpanded = !_devExpanded),
              child: Row(children: [
                const Icon(Icons.phone_android, size: 16, color: Colors.grey),
                const SizedBox(width: 6),
                Text('Device Information',
                  style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700,
                    color: Colors.grey.shade600)),
                const Spacer(),
                Icon(_devExpanded ? Icons.expand_less : Icons.expand_more,
                  size: 18, color: Colors.grey),
              ]),
            ),
            if (_devExpanded) ...[
              const SizedBox(height: 10),
              _InfoRow(label: 'OS',    value: p.osVersion),
              _InfoRow(label: 'Build', value: p.buildVersion),
              if (p.securityPatchLevel.isNotEmpty)
                _InfoRow(label: 'Security Patch',  value: p.securityPatchLevel),
              if (p.androidSdkVersion > 0)
                _InfoRow(label: 'SDK',             value: 'API ${p.androidSdkVersion}'),
              if (p.manufacturer.isNotEmpty)
                _InfoRow(label: 'Manufacturer',    value: p.manufacturer),
              if (p.hardware.isNotEmpty)
                _InfoRow(label: 'Hardware',        value: p.hardware),
              if (p.ramTotalMb > 0)
                _InfoRow(label: 'RAM',
                  value: p.ramTotalMb >= 1024
                    ? '${(p.ramTotalMb / 1024).toStringAsFixed(1)} GB'
                    : '${p.ramTotalMb} MB'),
              if (_devInfo != null) ...[
                _InfoRow(label: 'Android ID',      value: _devInfo!.id),
                _InfoRow(label: 'Fingerprint',
                  value: _devInfo!.fingerprint.length > 36
                    ? '${_devInfo!.fingerprint.substring(0, 36)}…'
                    : _devInfo!.fingerprint),
              ],
              const SizedBox(height: 8),
            ],
          ],
          const SizedBox(height: 20),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 3 — Network
// ─────────────────────────────────────────────────────────────────────────────

class _NetworkTab extends StatefulWidget {
  const _NetworkTab();
  @override
  State<_NetworkTab> createState() => _NetworkTabState();
}

class _NetworkTabState extends State<_NetworkTab> {
  bool _loading = true;
  List<ConnectivityResult> _conn = [];
  int?   _pingMs;
  bool   _serverReachable = false;
  List   _netEvents = [];
  String? _serverUrl;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    _serverUrl = await SecureStore.serverUrl();
    await Future.wait([_checkConn(), _pingServer(), _fetchNetEvents()]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  Future<void> _checkConn() async {
    try { _conn = await Connectivity().checkConnectivity(); }
    catch (_) { _conn = [ConnectivityResult.none]; }
  }

  Future<void> _pingServer() async {
    try {
      final sw = Stopwatch()..start();
      await (await ApiClient.fromStorage()).get('/api/agents/self/summary');
      sw.stop();
      _pingMs = sw.elapsedMilliseconds;
      _serverReachable = true;
    } catch (_) { _serverReachable = false; _pingMs = null; }
  }

  Future<void> _fetchNetEvents() async {
    try {
      final r = await (await ApiClient.fromStorage()).get('/api/agents/self/timeline');
      final all = (r['events'] ?? r['data'] ?? []) as List;
      _netEvents = all.where((e) {
        final t = (e['event_type'] ?? e['type'] ?? '').toString();
        return t.contains('connect') || t.contains('network') || t.contains('checkin');
      }).take(12).toList();
    } catch (_) {}
  }

  bool get _hasVpn    => _conn.contains(ConnectivityResult.vpn);
  bool get _hasWifi   => _conn.contains(ConnectivityResult.wifi);
  bool get _hasMobile => _conn.contains(ConnectivityResult.mobile);
  bool get _offline   => _conn.isEmpty || _conn.every((r) => r == ConnectivityResult.none);

  String get _connLabel {
    if (_offline) return 'Offline';
    final parts = <String>[];
    if (_hasVpn)    parts.add('VPN');
    if (_hasWifi)   parts.add('Wi-Fi');
    if (_hasMobile) parts.add('Mobile');
    if (_conn.contains(ConnectivityResult.ethernet)) parts.add('Ethernet');
    return parts.isEmpty ? 'Unknown' : parts.join(' + ');
  }

  Color get _connColor {
    if (_offline)  return _kRed;
    if (_hasVpn)   return _kGreen;
    if (_hasWifi)  return _kBlue;
    return _kAmber;
  }

  int get _networkScore {
    if (_offline) return 0;
    int s = 50;
    if (_hasVpn)          s += 30;
    if (_hasWifi)         s += 10;
    if (_hasMobile)       s += 15;
    if (_serverReachable) s += 10;
    return s.clamp(0, 100);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Connection header card
          Card(child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(children: [
              Row(children: [
                Container(
                  width: 52, height: 52,
                  decoration: BoxDecoration(
                    color: _connColor.withValues(alpha: .12),
                    borderRadius: BorderRadius.circular(14)),
                  child: Icon(_connIcon(), color: _connColor, size: 26),
                ),
                const SizedBox(width: 16),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  const Text('CONNECTION',
                    style: TextStyle(fontSize: 10, letterSpacing: 1.2, color: Colors.grey,
                      fontWeight: FontWeight.w700)),
                  const SizedBox(height: 2),
                  Text(_connLabel,
                    style: TextStyle(fontSize: 19, fontWeight: FontWeight.w800,
                      color: _connColor)),
                ])),
                _Pill(label: _offline ? 'OFFLINE' : 'ONLINE', color: _connColor),
              ]),
              if (_conn.any((r) => r != ConnectivityResult.none)) ...[
                const SizedBox(height: 14),
                Wrap(
                  spacing: 8, runSpacing: 6,
                  children: _conn.where((r) => r != ConnectivityResult.none)
                    .map((r) => _ConnChip(result: r)).toList(),
                ),
              ],
            ]),
          )),
          const SizedBox(height: 12),

          // Server connection
          _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const _SectionLabel('Server Connection'),
            const SizedBox(height: 10),
            _InfoRow(label: 'Server',    value: _serverUrl ?? '–'),
            _InfoRow(label: 'Reachable', value: _serverReachable ? 'Yes' : 'No'),
            _InfoRow(label: 'Latency',   value: _pingMs != null ? '${_pingMs}ms' : '–'),
            _InfoRow(label: 'Quality',   value: _latencyLabel()),
          ])),
          const SizedBox(height: 12),

          // Security assessment
          _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const _SectionLabel('Security Assessment'),
            const SizedBox(height: 12),
            Row(children: [
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  const Text('Network Score',
                    style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
                  const Spacer(),
                  Text('$_networkScore / 100',
                    style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700,
                      color: _riskColor(_networkScore))),
                ]),
                const SizedBox(height: 6),
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: LinearProgressIndicator(
                    value: _networkScore / 100, minHeight: 6,
                    backgroundColor: _riskColor(_networkScore).withValues(alpha: .15),
                    valueColor: AlwaysStoppedAnimation(_riskColor(_networkScore)),
                  ),
                ),
              ])),
            ]),
            const SizedBox(height: 14),
            _CheckRow(label: 'VPN Protection', pass: _hasVpn,
              detail: _hasVpn ? 'Traffic routed through VPN' : 'No VPN — traffic may be intercepted'),
            _CheckRow(label: 'Server Reachable', pass: _serverReachable,
              detail: _serverReachable ? 'XCloak backend is accessible' : 'Cannot reach XCloak server'),
            _CheckRow(label: 'Network Available', pass: !_offline,
              detail: _offline ? 'Device is offline' : 'Network connectivity confirmed'),
          ])),
          const SizedBox(height: 12),

          // Recent network events
          if (_netEvents.isNotEmpty)
            _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              const _SectionLabel('Recent Network Events'),
              const SizedBox(height: 10),
              ..._netEvents.map((e) {
                final type = (e['event_type'] ?? e['type'] ?? '').toString();
                final ts   = (e['created_at'] ?? e['timestamp'] ?? '').toString();
                return Padding(
                  padding: const EdgeInsets.only(bottom: 7),
                  child: Row(children: [
                    Icon(_netEventIcon(type), size: 16, color: _kBlue),
                    const SizedBox(width: 10),
                    Expanded(child: Text(type.replaceAll('_', ' '),
                      style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w500))),
                    Text(_timeAgo(ts),
                      style: const TextStyle(fontSize: 11, color: Colors.grey)),
                  ]),
                );
              }),
            ])),
          const SizedBox(height: 20),
        ],
      ),
    );
  }

  IconData _connIcon() {
    if (_hasVpn)    return Icons.vpn_lock;
    if (_hasWifi)   return Icons.wifi;
    if (_hasMobile) return Icons.signal_cellular_alt;
    return Icons.signal_wifi_off;
  }

  String _latencyLabel() {
    if (_pingMs == null) return '–';
    if (_pingMs! < 100)  return 'Excellent (${_pingMs}ms)';
    if (_pingMs! < 300)  return 'Good (${_pingMs}ms)';
    if (_pingMs! < 600)  return 'Fair (${_pingMs}ms)';
    return 'Poor (${_pingMs}ms)';
  }

  Color _riskColor(int score) =>
    score >= 80 ? _kGreen : score >= 55 ? _kAmber : _kRed;

  IconData _netEventIcon(String type) {
    if (type.contains('checkin'))  return Icons.sync;
    if (type.contains('connect'))  return Icons.cable;
    return Icons.network_check;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 4 — Tasks
// ─────────────────────────────────────────────────────────────────────────────

class _TasksTab extends StatefulWidget {
  const _TasksTab();
  @override
  State<_TasksTab> createState() => _TasksTabState();
}

class _TasksTabState extends State<_TasksTab> {
  bool _loading      = true;
  List _tasks        = [];
  int  _yaraCount    = 0;
  List _taskHistory  = [];
  String? _releasedVersion;
  String? _localVersion;
  bool _updateAvail  = false;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    _localVersion = (await PackageInfo.fromPlatform()).version;
    final c = await ApiClient.fromStorage();
    await Future.wait([
      _fetchTasks(c), _fetchYara(c), _fetchHistory(c), _fetchRelease(c),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  Future<void> _fetchTasks(ApiClient c) async {
    try {
      final r = await c.get('/api/agents/self/tasks');
      _tasks = (r['tasks'] ?? []) as List;
    } catch (_) {}
  }

  Future<void> _fetchYara(ApiClient c) async {
    try {
      final r = await c.get('/api/yara/rules/enabled');
      final rules = r['rules'] ?? r['data'] ?? [];
      _yaraCount = (rules as List).length;
    } catch (_) {}
  }

  Future<void> _fetchHistory(ApiClient c) async {
    try {
      final r = await c.get('/api/agents/self/timeline');
      final all = (r['events'] ?? r['data'] ?? []) as List;
      _taskHistory = all.where((e) {
        final t = (e['event_type'] ?? e['type'] ?? '').toString();
        return t.contains('task') || t.contains('scan') || t.contains('command');
      }).take(15).toList();
    } catch (_) {}
  }

  Future<void> _fetchRelease(ApiClient c) async {
    try {
      final r = await c.get('/api/agent-releases/android');
      _releasedVersion = r['version']?.toString();
      if (_releasedVersion != null && _localVersion != null) {
        _updateAvail = _releasedVersion != _localVersion;
      }
    } catch (_) {}
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator());

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(16),
        children: [
          // Summary chips
          Row(children: [
            _StatChip(value: '${_tasks.length}', label: 'Pending',
              color: _tasks.isEmpty ? _kGreen : _kAmber),
            const SizedBox(width: 8),
            _StatChip(value: '$_yaraCount', label: 'YARA Rules', color: _kPurple),
            const SizedBox(width: 8),
            _StatChip(value: '${_taskHistory.length}', label: 'Completed', color: _kBlue),
          ]),
          const SizedBox(height: 16),

          // Update banner
          if (_updateAvail)
            Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              decoration: BoxDecoration(
                gradient: LinearGradient(colors: [
                  _kPurple.withValues(alpha: .14), _kBlue.withValues(alpha: .07)]),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: _kPurple.withValues(alpha: .3))),
              child: Row(children: [
                const Icon(Icons.system_update_alt, color: _kPurple, size: 22),
                const SizedBox(width: 12),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  const Text('Agent Update Available',
                    style: TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700,
                      color: _kPurple)),
                  Text('v$_localVersion → v$_releasedVersion',
                    style: const TextStyle(fontSize: 12, color: Colors.grey)),
                ])),
                const Icon(Icons.arrow_forward_ios, size: 14, color: _kPurple),
              ]),
            ),

          // Pending tasks
          const _SectionLabel('Pending Tasks'),
          const SizedBox(height: 8),
          if (_tasks.isEmpty)
            Container(
              padding: const EdgeInsets.symmetric(vertical: 28),
              alignment: Alignment.center,
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                Icon(Icons.task_alt, size: 48, color: _kGreen.withValues(alpha: .45)),
                const SizedBox(height: 10),
                const Text('All clear — no pending tasks',
                  style: TextStyle(fontSize: 13.5, fontWeight: FontWeight.w600)),
                Text('Tasks dispatched from the admin console appear here.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 12, color: Colors.grey.shade500)),
              ]),
            )
          else ..._tasks.map((t) => _TaskCard(task: t as Map<String, dynamic>)),

          const SizedBox(height: 16),

          // Detection rules status
          _Card(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            const _SectionLabel('Detection Engine'),
            const SizedBox(height: 10),
            _InfoRow(label: 'YARA Rules Active', value: '$_yaraCount'),
            _InfoRow(label: 'Agent Version',     value: _localVersion ?? '–'),
            _InfoRow(label: 'Latest Release',    value: _releasedVersion ?? 'unknown'),
            _InfoRow(label: 'Up to Date',
              value: _updateAvail ? 'No — update available' : 'Yes'),
          ])),

          if (_taskHistory.isNotEmpty) ...[
            const SizedBox(height: 16),
            const _SectionLabel('Task History'),
            const SizedBox(height: 8),
            ..._taskHistory.map((e) {
              final type = (e['event_type'] ?? e['type'] ?? '').toString();
              final desc = (e['description'] ?? '').toString();
              final ts   = (e['created_at'] ?? e['timestamp'] ?? '').toString();
              return Container(
                margin: const EdgeInsets.only(bottom: 6),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainerLow,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: Theme.of(context).colorScheme.outlineVariant)),
                child: Row(children: [
                  Container(
                    width: 34, height: 34,
                    decoration: BoxDecoration(
                      color: _kBlue.withValues(alpha: .1),
                      borderRadius: BorderRadius.circular(9)),
                    child: Icon(_taskHistIcon(type), color: _kBlue, size: 16),
                  ),
                  const SizedBox(width: 12),
                  Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(type.replaceAll('_', ' '),
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                    if (desc.isNotEmpty)
                      Text(desc, style: const TextStyle(fontSize: 11.5, color: Colors.grey),
                        maxLines: 1, overflow: TextOverflow.ellipsis),
                  ])),
                  Text(_timeAgo(ts),
                    style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                ]),
              );
            }),
          ],
          const SizedBox(height: 20),
        ],
      ),
    );
  }

  IconData _taskHistIcon(String t) {
    if (t.contains('scan'))    return Icons.bug_report_outlined;
    if (t.contains('command')) return Icons.terminal;
    return Icons.assignment_turned_in_outlined;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Shared widgets
// ─────────────────────────────────────────────────────────────────────────────

class _AlertCard extends StatelessWidget {
  final Map<String, dynamic> alert;
  final bool compact;
  final bool expanded;
  final VoidCallback? onTap;
  const _AlertCard({required this.alert, this.compact = false,
    this.expanded = false, this.onTap});

  @override
  Widget build(BuildContext context) {
    final sev   = _parseSev(alert['severity'] ?? alert['level']);
    final rule  = (alert['rule_name'] ?? alert['name'] ?? 'Unknown Rule').toString();
    final desc  = (alert['description'] ?? alert['message'] ?? '').toString();
    final ts    = (alert['created_at'] ?? alert['timestamp'] ?? '').toString();
    final mitre = (alert['mitre_technique'] ?? alert['technique'] ?? '').toString();

    return GestureDetector(
      onTap: onTap,
      child: Container(
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(10),
          border: Border.all(color: sev.color.withValues(alpha: .3)),
          color: sev.color.withValues(alpha: .04)),
        clipBehavior: Clip.hardEdge,
        child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
          Container(width: 4, color: sev.color),
          Expanded(child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 10),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(child: Text(rule,
                  style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700),
                  maxLines: 1, overflow: TextOverflow.ellipsis)),
                const SizedBox(width: 8),
                _Pill(label: sev.label, color: sev.color),
              ]),
              if (desc.isNotEmpty) ...[
                const SizedBox(height: 4),
                Text(desc, style: const TextStyle(fontSize: 12, color: Colors.grey),
                  maxLines: compact ? 1 : (expanded ? null : 2),
                  overflow: compact || !expanded ? TextOverflow.ellipsis : null),
              ],
              const SizedBox(height: 6),
              Row(children: [
                if (mitre.isNotEmpty) ...[
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                    decoration: BoxDecoration(
                      color: _kPurple.withValues(alpha: .1),
                      borderRadius: BorderRadius.circular(4),
                      border: Border.all(color: _kPurple.withValues(alpha: .25))),
                    child: Text(mitre,
                      style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                        color: _kPurple)),
                  ),
                  const SizedBox(width: 8),
                ],
                Text(_timeAgo(ts), style: const TextStyle(fontSize: 11, color: Colors.grey)),
                if (!compact) ...[
                  const Spacer(),
                  Icon(expanded ? Icons.expand_less : Icons.expand_more,
                    size: 16, color: Colors.grey),
                ],
              ]),
              if (expanded && !compact) ...[
                const Divider(height: 16),
                ...alert.entries
                  .where((kv) => !const {
                    'rule_name', 'name', 'description', 'message',
                    'severity', 'level', 'created_at', 'timestamp',
                    'mitre_technique', 'technique',
                  }.contains(kv.key) && kv.value != null)
                  .map((kv) => Padding(
                    padding: const EdgeInsets.only(bottom: 3),
                    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text('${kv.key}:  ',
                        style: const TextStyle(fontSize: 11, color: Colors.grey,
                          fontWeight: FontWeight.w600)),
                      Expanded(child: Text(kv.value.toString(),
                        style: const TextStyle(fontSize: 11))),
                    ]),
                  )),
              ],
            ]),
          )),
        ]),
      ),
    );
  }
}

class _TaskCard extends StatelessWidget {
  final Map<String, dynamic> task;
  const _TaskCard({required this.task});

  @override
  Widget build(BuildContext context) {
    final type   = (task['task_type'] ?? task['type'] ?? 'task').toString();
    final status = (task['status'] ?? 'pending').toString();
    final ts     = (task['created_at'] ?? '').toString();
    final statusColor = switch (status.toLowerCase()) {
      'pending'                  => _kAmber,
      'running'                  => _kBlue,
      'done' || 'completed'      => _kGreen,
      _                          => Colors.grey,
    };

    return Container(
      margin: const EdgeInsets.only(bottom: 8),
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: statusColor.withValues(alpha: .3)),
        color: statusColor.withValues(alpha: .05)),
      child: Row(children: [
        Container(
          width: 40, height: 40,
          decoration: BoxDecoration(
            color: statusColor.withValues(alpha: .12),
            borderRadius: BorderRadius.circular(10)),
          child: Icon(_taskIcon(type), color: statusColor, size: 20),
        ),
        const SizedBox(width: 14),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(type.replaceAll('_', ' '),
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700)),
          if (ts.isNotEmpty)
            Text('Queued ${_timeAgo(ts)}',
              style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
        ])),
        _Pill(label: status.toUpperCase(), color: statusColor),
      ]),
    );
  }

  IconData _taskIcon(String type) {
    if (type.contains('scan'))     return Icons.bug_report_outlined;
    if (type.contains('collect'))  return Icons.download_outlined;
    if (type.contains('execute'))  return Icons.terminal;
    if (type.contains('isolate'))  return Icons.block;
    if (type.contains('update'))   return Icons.system_update_alt;
    return Icons.assignment_outlined;
  }
}

class _FilterChip extends StatelessWidget {
  final String label;
  final int count;
  final bool selected;
  final Color color;
  final VoidCallback onTap;
  const _FilterChip({required this.label, required this.count,
    required this.selected, required this.color, required this.onTap});

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: AnimatedContainer(
      duration: const Duration(milliseconds: 160),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: selected ? color.withValues(alpha: .14) : Colors.transparent,
        borderRadius: BorderRadius.circular(20),
        border: Border.all(
          color: selected ? color : Colors.grey.withValues(alpha: .3),
          width: selected ? 1.5 : 1)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Text(label, style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600,
          color: selected ? color : Colors.grey)),
        if (count > 0) ...[
          const SizedBox(width: 5),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
            decoration: BoxDecoration(
              color: selected ? color : Colors.grey.withValues(alpha: .3),
              borderRadius: BorderRadius.circular(10)),
            child: Text('$count', style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800,
              color: selected ? Colors.white : Colors.grey)),
          ),
        ],
      ]),
    ),
  );
}

class _ConnChip extends StatelessWidget {
  final ConnectivityResult result;
  const _ConnChip({required this.result});

  @override
  Widget build(BuildContext context) {
    final (label, icon, color) = switch (result) {
      ConnectivityResult.wifi      => ('Wi-Fi',     Icons.wifi,                _kBlue),
      ConnectivityResult.mobile    => ('Mobile',    Icons.signal_cellular_alt, _kGreen),
      ConnectivityResult.vpn       => ('VPN',       Icons.vpn_lock,            _kGreen),
      ConnectivityResult.ethernet  => ('Ethernet',  Icons.settings_ethernet,   _kBlue),
      ConnectivityResult.bluetooth => ('Bluetooth', Icons.bluetooth,           _kPurple),
      _                            => ('Other',     Icons.device_unknown,      Colors.grey),
    };
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color: color.withValues(alpha: .1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: color.withValues(alpha: .3))),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, size: 14, color: color),
        const SizedBox(width: 5),
        Text(label, style: TextStyle(fontSize: 12, fontWeight: FontWeight.w600, color: color)),
      ]),
    );
  }
}

class _StatChip extends StatelessWidget {
  final String value, label;
  final Color  color;
  const _StatChip({required this.value, required this.label, required this.color});

  @override
  Widget build(BuildContext context) => Expanded(child: Container(
    padding: const EdgeInsets.symmetric(vertical: 10),
    decoration: BoxDecoration(
      color: color.withValues(alpha: .08),
      borderRadius: BorderRadius.circular(12),
      border: Border.all(color: color.withValues(alpha: .2))),
    child: Column(children: [
      Text(value, style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800, color: color)),
      const SizedBox(height: 2),
      Text(label, style: TextStyle(fontSize: 10, color: color.withValues(alpha: .8)),
        textAlign: TextAlign.center, maxLines: 1, overflow: TextOverflow.ellipsis),
    ]),
  ));
}

class _ActionTile extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;
  const _ActionTile({required this.icon, required this.label,
    required this.color, required this.onTap});

  @override
  Widget build(BuildContext context) => Expanded(child: InkWell(
    borderRadius: BorderRadius.circular(12),
    onTap: onTap,
    child: Container(
      padding: const EdgeInsets.symmetric(vertical: 14),
      decoration: BoxDecoration(
        color: color.withValues(alpha: .07),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withValues(alpha: .25))),
      child: Column(children: [
        Container(
          width: 38, height: 38,
          decoration: BoxDecoration(
            color: color.withValues(alpha: .12),
            borderRadius: BorderRadius.circular(10)),
          child: Icon(icon, color: color, size: 20),
        ),
        const SizedBox(height: 7),
        Text(label, style: TextStyle(fontSize: 10.5, color: color,
          fontWeight: FontWeight.w700), textAlign: TextAlign.center),
      ]),
    ),
  ));
}

class _SubScore extends StatelessWidget {
  final String label;
  final int score;
  const _SubScore({required this.label, required this.score});

  Color get _color => score >= 85 ? _kGreen : score >= 65 ? _kAmber : _kRed;

  @override
  Widget build(BuildContext context) => Expanded(child: Column(children: [
    Stack(alignment: Alignment.center, children: [
      SizedBox(
        width: 44, height: 44,
        child: CircularProgressIndicator(
          value: score / 100, strokeWidth: 4,
          backgroundColor: _color.withValues(alpha: .15),
          valueColor: AlwaysStoppedAnimation(_color),
          strokeCap: StrokeCap.round),
      ),
      Text('$score', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800, color: _color)),
    ]),
    const SizedBox(height: 4),
    Text(label, style: const TextStyle(fontSize: 10, color: Colors.grey)),
  ]));
}

class _GroupHeader extends StatelessWidget {
  final String label;
  final int? score;
  const _GroupHeader({required this.label, this.score});

  Color _scoreColor(int s) => s >= 85 ? _kGreen : s >= 65 ? _kAmber : _kRed;

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 8),
    child: Row(children: [
      Container(width: 3, height: 14,
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.primary,
          borderRadius: BorderRadius.circular(2))),
      const SizedBox(width: 8),
      Text(label, style: TextStyle(fontSize: 11.5, fontWeight: FontWeight.w800,
        letterSpacing: .8,
        color: Theme.of(context).colorScheme.onSurface.withValues(alpha: .7))),
      if (score != null) ...[
        const Spacer(),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
          decoration: BoxDecoration(
            color: _scoreColor(score!).withValues(alpha: .12),
            borderRadius: BorderRadius.circular(5)),
          child: Text('$score%',
            style: TextStyle(fontSize: 10.5, fontWeight: FontWeight.w800,
              color: _scoreColor(score!))),
        ),
      ],
    ]),
  );
}

class _CheckRow extends StatelessWidget {
  final String label, detail;
  final bool   pass;
  const _CheckRow({required this.label, required this.pass, required this.detail});

  @override
  Widget build(BuildContext context) {
    final color = pass ? _kGreen : _kRed;
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
      decoration: BoxDecoration(
        color: color.withValues(alpha: .04),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: .2))),
      child: Row(children: [
        Icon(pass ? Icons.check_circle_outline : Icons.cancel_outlined,
          color: color, size: 20),
        const SizedBox(width: 12),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
          Text(detail, style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
        ])),
        _Pill(label: pass ? 'PASS' : 'FAIL', color: color),
      ]),
    );
  }
}

class _Pill extends StatelessWidget {
  final String label;
  final Color  color;
  const _Pill({required this.label, required this.color});

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
    decoration: BoxDecoration(
      color: color.withValues(alpha: .1),
      borderRadius: BorderRadius.circular(5),
      border: Border.all(color: color.withValues(alpha: .25))),
    child: Text(label, style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800,
      color: color, letterSpacing: .7)),
  );
}

class _Card extends StatelessWidget {
  final Widget child;
  const _Card({required this.child});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.symmetric(horizontal: 16),
    child: Card(child: Padding(padding: const EdgeInsets.all(16), child: child)),
  );
}

class _SectionLabel extends StatelessWidget {
  final String text;
  const _SectionLabel(this.text);

  @override
  Widget build(BuildContext context) => Text(text,
    style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w800,
      letterSpacing: 1.1, color: Colors.grey));
}

class _InfoRow extends StatelessWidget {
  final String label, value;
  const _InfoRow({required this.label, required this.value});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(children: [
      Text(label, style: const TextStyle(fontSize: 12.5, color: Colors.grey)),
      const SizedBox(width: 8),
      Expanded(child: Text(value,
        style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600),
        textAlign: TextAlign.end, overflow: TextOverflow.ellipsis)),
    ]),
  );
}

class _ProgressRow extends StatelessWidget {
  final IconData icon;
  final Color    iconColor;
  final String   label;
  final double   value; // 0.0–1.0
  final Color    color;
  const _ProgressRow({
    required this.icon, required this.iconColor,
    required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) => Row(children: [
    Icon(icon, size: 16, color: iconColor),
    const SizedBox(width: 8),
    Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(label, style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w500)),
      const SizedBox(height: 4),
      ClipRRect(
        borderRadius: BorderRadius.circular(3),
        child: LinearProgressIndicator(
          value: value.clamp(0.0, 1.0),
          minHeight: 5,
          backgroundColor: color.withValues(alpha: .15),
          valueColor: AlwaysStoppedAnimation(color),
        ),
      ),
    ])),
  ]);
}

// ─────────────────────────────────────────────────────────────────────────────
// Ring painter
// ─────────────────────────────────────────────────────────────────────────────

class _RingPainter extends CustomPainter {
  final double progress;
  final Color  color;
  final double strokeWidth;
  const _RingPainter({required this.progress, required this.color, this.strokeWidth = 10});

  @override
  void paint(Canvas canvas, Size size) {
    final cx   = size.width  / 2;
    final cy   = size.height / 2;
    final r    = min(cx, cy) - strokeWidth / 2;
    final rect = Rect.fromCircle(center: Offset(cx, cy), radius: r);

    // Background track
    canvas.drawArc(rect, -pi / 2, 2 * pi, false, Paint()
      ..color       = color.withValues(alpha: .12)
      ..style       = PaintingStyle.stroke
      ..strokeWidth = strokeWidth
      ..strokeCap   = StrokeCap.round);

    // Progress arc with soft glow
    if (progress > 0) {
      canvas.drawArc(rect, -pi / 2, 2 * pi * progress, false, Paint()
        ..color       = color
        ..style       = PaintingStyle.stroke
        ..strokeWidth = strokeWidth
        ..strokeCap   = StrokeCap.round
        ..maskFilter  = MaskFilter.blur(BlurStyle.solid, strokeWidth * 0.25));
    }
  }

  @override
  bool shouldRepaint(_RingPainter old) =>
    old.progress != progress || old.color != color || old.strokeWidth != strokeWidth;
}
