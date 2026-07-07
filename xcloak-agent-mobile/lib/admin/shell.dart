import 'package:flutter/material.dart';

import '../screens/mode_select.dart';
import '../services/secure_storage.dart';
import 'api.dart';
import 'screens/compliance.dart';
import 'screens/detection.dart';
import 'screens/hunt.dart';
import 'screens/inventory.dart';
import 'screens/overview.dart';
import 'screens/platform.dart';
import 'screens/response.dart';

// ── 10-group nav matching the web sidebar ─────────────────────────────────────

class _NavGroup {
  final String label;
  final IconData icon;
  final bool platformOnly;
  final List<_NavItem> items;
  const _NavGroup(this.label, this.icon, this.items, {this.platformOnly = false});
}

class _NavItem {
  final int id;
  final IconData icon;
  final String label;
  const _NavItem(this.id, this.icon, this.label);
}

const _nav = [
  _NavGroup('OVERVIEW', Icons.dashboard_outlined, [
    _NavItem(0,  Icons.dashboard,           'Dashboard'),
    _NavItem(2,  Icons.lan,                 'Network Map'),
    _NavItem(3,  Icons.route,               'Attack Paths'),
    _NavItem(49, Icons.crisis_alert,        'Risk Posture'),
  ]),
  _NavGroup('MONITORING', Icons.monitor_heart_outlined, [
    _NavItem(1,  Icons.computer,            'Agents'),
    _NavItem(4,  Icons.timeline,            'Timeline'),
    _NavItem(26, Icons.terminal,            'Live Logs'),
    _NavItem(27, Icons.search,              'Log Search'),
    _NavItem(28, Icons.source,              'Log Sources'),
  ]),
  _NavGroup('DETECTION', Icons.warning_amber_outlined, [
    _NavItem(5,  Icons.notifications,       'Alerts'),
    _NavItem(6,  Icons.bolt,                'Incidents'),
    _NavItem(7,  Icons.person_search,       'UEBA'),
    _NavItem(8,  Icons.person_off,          'Insider Threat'),
    _NavItem(20, Icons.show_chart,          'Net Behavior'),
    _NavItem(25, Icons.bar_chart,           'Behavioral'),
    _NavItem(31, Icons.compare_arrows,      'Correlation'),
    _NavItem(30, Icons.bubble_chart,        'Alert Clusters'),
  ]),
  _NavGroup('INTEL & HUNT', Icons.gps_fixed_outlined, [
    _NavItem(21, Icons.gps_fixed,           'Threat Intel'),
    _NavItem(19, Icons.people,              'Threat Actors'),
    _NavItem(22, Icons.rule,                'Sigma Rules'),
    _NavItem(23, Icons.pest_control,        'YARA Rules'),
    _NavItem(24, Icons.fingerprint,         'JA3 Fingerprints'),
    _NavItem(18, Icons.manage_search,       'Hunt Workbench'),
    _NavItem(29, Icons.travel_explore,      'Threat Hunt'),
    _NavItem(41, Icons.folder_copy,         'DFIR'),
    _NavItem(17, Icons.sports_esports,      'Deception'),
  ]),
  _NavGroup('CLOUD & INFRA', Icons.cloud_outlined, [
    _NavItem(9,  Icons.cloud,               'Cloud Security'),
    _NavItem(10, Icons.email,               'Email Security'),
    _NavItem(11, Icons.view_in_ar,          'Containers/K8s'),
    _NavItem(12, Icons.account_tree,        'AD Attacks'),
    _NavItem(13, Icons.link,                'Supply Chain'),
    _NavItem(16, Icons.settings_input_component, 'OT/ICS'),
    _NavItem(14, Icons.memory,              'Process Injection'),
    _NavItem(15, Icons.hide_source,         'Defense Evasion'),
  ]),
  _NavGroup('RESPONSE', Icons.shield_outlined, [
    _NavItem(33, Icons.folder_special,      'Cases'),
    _NavItem(34, Icons.play_circle,         'Playbooks'),
    _NavItem(35, Icons.check_circle,        'Approval Queue'),
    _NavItem(36, Icons.bug_report,          'Vulnerabilities'),
    _NavItem(37, Icons.low_priority,        'Vuln Queue'),
    _NavItem(32, Icons.volume_off,          'Suppression'),
    _NavItem(38, Icons.lock,                'Quarantine'),
    _NavItem(42, Icons.code,                'Script Runner'),
    _NavItem(40, Icons.schedule,            'Scheduled Tasks'),
    _NavItem(39, Icons.shield,              'Firewall'),
  ]),
  _NavGroup('COMPLIANCE', Icons.checklist_outlined, [
    _NavItem(45, Icons.description,         'Reports'),
    _NavItem(46, Icons.checklist,           'Frameworks'),
    _NavItem(47, Icons.business,            'Executive'),
    _NavItem(48, Icons.analytics,           'SOC Metrics'),
  ]),
  _NavGroup('ASSETS', Icons.inventory_2_outlined, [
    _NavItem(43, Icons.inventory_2,         'Assets (CMDB)'),
    _NavItem(44, Icons.smartphone,          'Mobile (MDM)'),
  ]),
  _NavGroup('AI & SYSTEM', Icons.smart_toy_outlined, [
    _NavItem(50, Icons.smart_toy,           'AI Assistant'),
    _NavItem(51, Icons.settings,            'Settings'),
  ]),
  _NavGroup('PLATFORM', Icons.domain_outlined, [
    _NavItem(52, Icons.domain,              'Tenants'),
  ], platformOnly: true),
];

// Bottom quick-nav items (most critical for SOC mobile)
const _quickNav = [
  (0,  Icons.dashboard,       'Dashboard'),
  (5,  Icons.notifications,   'Alerts'),
  (33, Icons.folder_special,  'Cases'),
  (50, Icons.smart_toy,       'AI'),
];

// ─────────────────────────────────────────────────────────────────────────────
// AdminApp
// ─────────────────────────────────────────────────────────────────────────────

class AdminApp extends StatefulWidget {
  final DashboardApi api;
  const AdminApp({super.key, required this.api});
  @override State<AdminApp> createState() => _AdminAppState();
}

class _AdminAppState extends State<AdminApp> {
  int    _sel        = 0;
  bool   _darkMode   = false;
  int    _alertBadge = 0;
  final _scaffoldKey = GlobalKey<ScaffoldState>();
  String? _adminEmail;
  String? _adminRole;

  @override
  void initState() {
    super.initState();
    _loadProfile();
    _pollAlertCount();
  }

  Future<void> _loadProfile() async {
    final email = await SecureStore.adminEmail();
    final role  = await SecureStore.adminRole();
    if (!mounted) return;
    setState(() { _adminEmail = email; _adminRole = role; });
  }

  Future<void> _pollAlertCount() async {
    final alerts = await widget.api.alerts(status: 'open', per: 1);
    if (!mounted) return;
    final r = await widget.api.overview();
    final count = (r?['open_alerts'] ?? r?['active_alerts'] ?? alerts.length);
    setState(() => _alertBadge = count is int ? count : 0);
  }

  String get _title {
    for (final g in _nav) {
      for (final item in g.items) {
        if (item.id == _sel) return item.label;
      }
    }
    return 'Dashboard';
  }

  Widget _body() {
    final api = widget.api;
    return switch (_sel) {
      0  => DashboardScreen(api: api),
      1  => AgentsScreen(api: api),
      2  => NetworkMapScreen(api: api),
      3  => AttackPathsScreen(api: api),
      4  => TimelineScreen(api: api),
      5  => AlertsScreen(api: api),
      6  => IncidentsScreen(api: api),
      7  => UEBAScreen(api: api),
      8  => InsiderThreatScreen(api: api),
      9  => ItdrScreen(api: api, category: 'cloud',           title: 'Cloud Security'),
      10 => ItdrScreen(api: api, category: 'email',           title: 'Email Security'),
      11 => ItdrScreen(api: api, category: 'container',       title: 'Containers/K8s'),
      12 => ItdrScreen(api: api, category: 'ad',              title: 'AD Attacks'),
      13 => ItdrScreen(api: api, category: 'supply_chain',    title: 'Supply Chain'),
      14 => ItdrScreen(api: api, category: 'process_inject',  title: 'Process Injection'),
      15 => ItdrScreen(api: api, category: 'defense_evasion', title: 'Defense Evasion'),
      16 => ItdrScreen(api: api, category: 'ot_ics',          title: 'OT/ICS'),
      17 => DeceptionScreen(api: api),
      18 => HuntWorkbenchScreen(api: api),
      19 => ThreatActorsScreen(api: api),
      20 => NBAScreen(api: api),
      21 => ThreatIntelScreen(api: api),
      22 => SigmaRulesScreen(api: api),
      23 => YaraRulesScreen(api: api),
      24 => JA3Screen(api: api),
      25 => BehavioralScreen(api: api),
      26 => LiveLogsScreen(api: api),
      27 => LogSearchScreen(api: api),
      28 => LogSourcesScreen(api: api),
      29 => ThreatHuntScreen(api: api),
      30 => ClustersScreen(api: api),
      31 => CorrelationScreen(api: api),
      32 => SuppressionScreen(api: api),
      33 => CasesScreen(api: api),
      34 => PlaybooksScreen(api: api),
      35 => ApprovalsScreen(api: api),
      36 => VulnerabilitiesScreen(api: api),
      37 => VulnQueueScreen(api: api),
      38 => QuarantineScreen(api: api),
      39 => FirewallScreen(api: api),
      40 => ScheduledTasksScreen(api: api),
      41 => DFIRScreen(api: api),
      42 => ScriptRunnerScreen(api: api),
      43 => AssetsScreen(api: api),
      44 => MDMScreen(api: api),
      45 => ReportsScreen(api: api),
      46 => FrameworksScreen(api: api),
      47 => ExecutiveScreen(api: api),
      48 => SOCMetricsScreen(api: api),
      49 => RiskPostureScreen(api: api),
      50 => AIAssistantScreen(api: api),
      51 => SettingsScreen(api: api),
      52 => TenantsScreen(api: api),
      _  => DashboardScreen(api: api),
    };
  }

  void _navigate(int id) {
    setState(() => _sel = id);
    Navigator.pop(context); // close drawer
  }

  Future<void> _signOut() async {
    await SecureStore.clearAdminSession();
    if (!mounted) return;
    Navigator.pushAndRemoveUntil(
      context,
      MaterialPageRoute(builder: (_) => const ModeSelectScreen()),
      (_) => false,
    );
  }

  Future<void> _switchToAgent() async {
    if (!mounted) return;
    Navigator.pushAndRemoveUntil(
      context,
      MaterialPageRoute(builder: (_) => const ModeSelectScreen()),
      (_) => false,
    );
  }

  // Quick-nav bottom bar index → _sel mapping
  int get _quickIdx {
    for (int i = 0; i < _quickNav.length; i++) {
      if (_quickNav[i].$1 == _sel) return i;
    }
    return -1;
  }

  @override
  Widget build(BuildContext context) {
    final brightness = _darkMode ? Brightness.dark : Brightness.light;
    final cs = ColorScheme.fromSeed(
      seedColor: const Color(0xFF1565C0), brightness: brightness);

    return Theme(
      data: ThemeData(
        colorScheme: cs, useMaterial3: true,
        brightness: brightness,
        cardTheme: CardTheme(
          elevation: 0,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(12),
            side: BorderSide(color: _darkMode ? const Color(0xFF1E293B) : const Color(0xFFE2E8F0))),
          margin: EdgeInsets.zero),
        inputDecorationTheme: InputDecorationTheme(
          filled: true,
          fillColor: _darkMode ? const Color(0xFF1E293B) : const Color(0xFFF8FAFC),
          border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
          contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14)),
        appBarTheme: AppBarTheme(
          centerTitle: false, elevation: 0, scrolledUnderElevation: 1,
          backgroundColor: _darkMode ? const Color(0xFF0F172A) : null),
        scaffoldBackgroundColor: _darkMode ? const Color(0xFF0F172A) : null,
      ),
      child: Scaffold(
      key: _scaffoldKey,
      appBar: AppBar(
        leading: IconButton(
          icon: const Icon(Icons.menu),
          onPressed: () => _scaffoldKey.currentState?.openDrawer(),
        ),
        titleSpacing: 0,
        title: Row(children: [
          Container(
            width: 26, height: 26,
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(7),
              color: cs.primary.withOpacity(.12),
            ),
            child: Icon(Icons.admin_panel_settings, color: cs.primary, size: 15),
          ),
          const SizedBox(width: 8),
          Expanded(child: Text(_title,
            style: const TextStyle(fontSize: 15, fontWeight: FontWeight.w700),
            overflow: TextOverflow.ellipsis)),
        ]),
        actions: [
          IconButton(
            icon: Icon(_darkMode ? Icons.light_mode_outlined : Icons.dark_mode_outlined),
            tooltip: 'Toggle Theme',
            onPressed: () => setState(() => _darkMode = !_darkMode),
          ),
          IconButton(
            icon: const Icon(Icons.refresh_outlined),
            tooltip: 'Refresh alerts',
            onPressed: _pollAlertCount,
          ),
          IconButton(
            icon: const Icon(Icons.phone_android_outlined),
            tooltip: 'Switch to Agent Mode',
            onPressed: _switchToAgent,
          ),
        ],
      ),
      drawer: _AdminDrawer(
        sel: _sel,
        adminEmail: _adminEmail,
        adminRole: _adminRole,
        onNavigate: _navigate,
        onSignOut: _signOut,
        onAgentMode: _switchToAgent,
      ),
      body: _body(),
      bottomNavigationBar: NavigationBar(
        selectedIndex: _quickIdx < 0 ? 0 : _quickIdx,
        onDestinationSelected: (i) {
          setState(() => _sel = _quickNav[i].$1);
          if (_quickNav[i].$1 == 5) _pollAlertCount();
        },
        destinations: [
          for (int i = 0; i < _quickNav.length; i++)
            NavigationDestination(
              icon: i == 1 && _alertBadge > 0
                ? Badge(
                    label: Text(_alertBadge > 99 ? '99+' : '$_alertBadge'),
                    child: Icon(_quickNav[i].$2))
                : Icon(_quickNav[i].$2),
              label: _quickNav[i].$3,
            ),
        ],
      ),
    ));
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Advanced Drawer
// ─────────────────────────────────────────────────────────────────────────────

class _AdminDrawer extends StatefulWidget {
  final int sel;
  final String? adminEmail;
  final String? adminRole;
  final void Function(int) onNavigate;
  final VoidCallback onSignOut;
  final VoidCallback onAgentMode;

  const _AdminDrawer({
    required this.sel,
    required this.adminEmail,
    required this.adminRole,
    required this.onNavigate,
    required this.onSignOut,
    required this.onAgentMode,
  });

  @override State<_AdminDrawer> createState() => _AdminDrawerState();
}

class _AdminDrawerState extends State<_AdminDrawer> {
  String _query = '';
  final _searchCtrl = TextEditingController();
  // groups that are currently expanded; default all expanded
  final _expanded = <String>{};
  @override
  void initState() {
    super.initState();
    // Expand the group that contains the active selection
    _expandActiveGroup();
  }

  void _expandActiveGroup() {
    for (final g in _nav) {
      if (g.items.any((i) => i.id == widget.sel)) {
        _expanded.add(g.label);
      }
    }
  }

  @override
  void didUpdateWidget(_AdminDrawer old) {
    super.didUpdateWidget(old);
    if (old.sel != widget.sel) _expandActiveGroup();
  }

  @override
  void dispose() { _searchCtrl.dispose(); super.dispose(); }

  List<_NavGroup> get _filtered {
    final q = _query.toLowerCase().trim();
    if (q.isEmpty) return _nav;
    return _nav
      .map((g) => _NavGroup(g.label, g.icon,
          g.items.where((i) => i.label.toLowerCase().contains(q)).toList(),
          platformOnly: g.platformOnly))
      .where((g) => g.items.isNotEmpty)
      .toList();
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Drawer(
      child: Column(children: [
        // ── Header ───────────────────────────────────────────────────────
        Container(
          padding: const EdgeInsets.fromLTRB(16, 52, 16, 16),
          width: double.infinity,
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft, end: Alignment.bottomRight,
              colors: [cs.primary, cs.primary.withBlue(200)],
            ),
          ),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Container(
                width: 46, height: 46,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: Colors.white.withOpacity(.2),
                  border: Border.all(color: Colors.white.withOpacity(.3)),
                ),
                child: const Icon(Icons.admin_panel_settings, color: Colors.white, size: 24),
              ),
              const SizedBox(width: 12),
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                const Text('XCloak Admin',
                  style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.w800)),
                const Text('Security Suite',
                  style: TextStyle(color: Colors.white70, fontSize: 11)),
              ]),
            ]),
            if (widget.adminEmail != null) ...[
              const SizedBox(height: 12),
              Row(children: [
                const Icon(Icons.person_outline, color: Colors.white70, size: 14),
                const SizedBox(width: 6),
                Expanded(child: Text(widget.adminEmail!,
                  style: const TextStyle(color: Colors.white, fontSize: 12),
                  overflow: TextOverflow.ellipsis)),
              ]),
            ],
            if (widget.adminRole != null) ...[
              const SizedBox(height: 6),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(.15),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: Colors.white.withOpacity(.3)),
                ),
                child: Text(widget.adminRole!.toUpperCase(),
                  style: const TextStyle(color: Colors.white, fontSize: 10, fontWeight: FontWeight.w700, letterSpacing: .8)),
              ),
            ],
          ]),
        ),

        // ── Search ───────────────────────────────────────────────────────
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
          child: TextField(
            controller: _searchCtrl,
            decoration: InputDecoration(
              hintText: 'Search sections…',
              hintStyle: const TextStyle(fontSize: 13),
              prefixIcon: const Icon(Icons.search, size: 18),
              suffixIcon: _query.isNotEmpty
                ? IconButton(
                    icon: const Icon(Icons.close, size: 16),
                    onPressed: () { setState(() { _query = ''; _searchCtrl.clear(); }); })
                : null,
              isDense: true,
              contentPadding: const EdgeInsets.symmetric(vertical: 9),
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
            ),
            onChanged: (v) => setState(() => _query = v),
          ),
        ),

        // ── Nav ──────────────────────────────────────────────────────────
        Expanded(
          child: ListView(
            padding: const EdgeInsets.only(bottom: 8),
            children: [
              for (final g in _filtered) ...[
                _GroupTile(
                  group: g,
                  sel: widget.sel,
                  expanded: _query.isNotEmpty || _expanded.contains(g.label),
                  onToggle: () => setState(() {
                    if (_expanded.contains(g.label)) _expanded.remove(g.label);
                    else _expanded.add(g.label);
                  }),
                  onNavigate: widget.onNavigate,
                ),
              ],
            ],
          ),
        ),

        // ── Footer ───────────────────────────────────────────────────────
        const Divider(height: 1),
        ListTile(
          dense: true,
          leading: Icon(Icons.phone_android_outlined, color: cs.primary, size: 19),
          title: Text('Switch to Agent Mode',
            style: TextStyle(color: cs.primary, fontWeight: FontWeight.w600, fontSize: 13)),
          trailing: Icon(Icons.chevron_right, color: cs.primary, size: 18),
          onTap: widget.onAgentMode,
        ),
        ListTile(
          dense: true,
          leading: const Icon(Icons.logout, color: Colors.redAccent, size: 19),
          title: const Text('Sign Out',
            style: TextStyle(color: Colors.redAccent, fontWeight: FontWeight.w600, fontSize: 13)),
          onTap: () async {
            Navigator.pop(context); // close drawer first
            await Future.delayed(const Duration(milliseconds: 200));
            widget.onSignOut();
          },
        ),
        const SizedBox(height: 8),
      ]),
    );
  }
}

// ── Collapsible group tile ────────────────────────────────────────────────────

class _GroupTile extends StatelessWidget {
  final _NavGroup group;
  final int sel;
  final bool expanded;
  final VoidCallback onToggle;
  final void Function(int) onNavigate;

  const _GroupTile({
    required this.group,
    required this.sel,
    required this.expanded,
    required this.onToggle,
    required this.onNavigate,
  });

  bool get _hasActive => group.items.any((i) => i.id == sel);

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Group header
        InkWell(
          onTap: onToggle,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
            child: Row(children: [
              if (_hasActive)
                Container(
                  width: 3, height: 14, margin: const EdgeInsets.only(right: 6),
                  decoration: BoxDecoration(color: cs.primary, borderRadius: BorderRadius.circular(2)),
                )
              else
                const SizedBox(width: 9),
              Icon(group.icon, size: 13, color: _hasActive ? cs.primary : cs.onSurfaceVariant),
              const SizedBox(width: 6),
              Text(group.label, style: TextStyle(
                fontSize: 10, fontWeight: FontWeight.w800, letterSpacing: 1.2,
                color: _hasActive ? cs.primary : cs.onSurfaceVariant)),
              const SizedBox(width: 4),
              Text('(${group.items.length})',
                style: TextStyle(fontSize: 9, color: cs.onSurfaceVariant.withOpacity(.6))),
              const Spacer(),
              Icon(expanded ? Icons.expand_less : Icons.expand_more,
                size: 16, color: cs.onSurfaceVariant),
            ]),
          ),
        ),

        // Items
        if (expanded)
          for (final item in group.items)
            _NavTile(item: item, active: item.id == sel, onNavigate: onNavigate),
      ],
    );
  }
}

class _NavTile extends StatelessWidget {
  final _NavItem item;
  final bool active;
  final void Function(int) onNavigate;
  const _NavTile({required this.item, required this.active, required this.onNavigate});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListTile(
      contentPadding: const EdgeInsets.only(left: 36, right: 12),
      leading: Icon(item.icon, size: 17,
        color: active ? cs.primary : cs.onSurfaceVariant),
      title: Text(item.label, style: TextStyle(
        fontSize: 13,
        fontWeight: active ? FontWeight.w700 : FontWeight.normal,
        color: active ? cs.primary : null,
      )),
      selected: active,
      selectedTileColor: cs.primary.withOpacity(.08),
      visualDensity: VisualDensity.compact,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      onTap: () => onNavigate(item.id),
    );
  }
}
