import 'package:flutter/material.dart';

import '../screens/status_screen.dart';
import '../services/secure_storage.dart';
import 'api.dart';
import 'screens/compliance.dart';
import 'screens/detection.dart';
import 'screens/hunt.dart';
import 'screens/inventory.dart';
import 'screens/overview.dart';
import 'screens/platform.dart';
import 'screens/response.dart';

// Section indices
const _kSections = [
  // top level
  (0,  Icons.dashboard,           'Dashboard',        ''),
  (1,  Icons.computer,            'Agents',           ''),
  (2,  Icons.lan,                 'Network Map',      ''),
  (3,  Icons.route,               'Attack Paths',     ''),
  (4,  Icons.timeline,            'Timeline',         ''),
  // detection
  (5,  Icons.notifications,       'Alerts',           'DETECTION'),
  (6,  Icons.bolt,                'Incidents',        'DETECTION'),
  (7,  Icons.person_search,       'UEBA',             'DETECTION'),
  (8,  Icons.person_off,          'Insider Threat',   'DETECTION'),
  (9,  Icons.cloud,               'Cloud Security',   'DETECTION'),
  (10, Icons.email,               'Email Security',   'DETECTION'),
  (11, Icons.view_in_ar,          'Containers/K8s',   'DETECTION'),
  (12, Icons.account_tree,        'AD Attacks',       'DETECTION'),
  (13, Icons.link,                'Supply Chain',     'DETECTION'),
  (14, Icons.memory,              'Process Injection','DETECTION'),
  (15, Icons.hide_source,         'Defense Evasion',  'DETECTION'),
  (16, Icons.settings_input_component, 'OT/ICS',      'DETECTION'),
  (17, Icons.sports_esports,      'Deception',        'DETECTION'),
  (18, Icons.manage_search,       'Hunt Workbench',   'DETECTION'),
  (19, Icons.people,              'Threat Actors',    'DETECTION'),
  (20, Icons.show_chart,          'Net Behavior',     'DETECTION'),
  (21, Icons.gps_fixed,           'Threat Intel',     'DETECTION'),
  (22, Icons.rule,                'Sigma Rules',      'DETECTION'),
  (23, Icons.pest_control,        'YARA Rules',       'DETECTION'),
  (24, Icons.fingerprint,         'JA3 Fingerprints', 'DETECTION'),
  (25, Icons.bar_chart,           'Behavioral',       'DETECTION'),
  (26, Icons.terminal,            'Live Logs',        'DETECTION'),
  (27, Icons.search,              'Log Search',       'DETECTION'),
  (28, Icons.source,              'Log Sources',      'DETECTION'),
  (29, Icons.travel_explore,      'Threat Hunt',      'DETECTION'),
  (30, Icons.bubble_chart,        'Alert Clusters',   'DETECTION'),
  (31, Icons.compare_arrows,      'Correlation',      'DETECTION'),
  (32, Icons.volume_off,          'Suppression',      'DETECTION'),
  // response
  (33, Icons.folder_special,      'Cases',            'RESPONSE'),
  (34, Icons.play_circle,         'Playbooks',        'RESPONSE'),
  (35, Icons.check_circle,        'Approval Queue',   'RESPONSE'),
  (36, Icons.bug_report,          'Vulnerabilities',  'RESPONSE'),
  (37, Icons.low_priority,        'Vuln Queue',       'RESPONSE'),
  (38, Icons.lock,                'Quarantine',       'RESPONSE'),
  (39, Icons.shield,              'Firewall',         'RESPONSE'),
  (40, Icons.schedule,            'Scheduled Tasks',  'RESPONSE'),
  (41, Icons.folder_copy,         'DFIR',             'RESPONSE'),
  (42, Icons.code,                'Script Runner',    'RESPONSE'),
  // inventory
  (43, Icons.inventory_2,         'Assets (CMDB)',    'INVENTORY'),
  (44, Icons.smartphone,          'Mobile (MDM)',     'INVENTORY'),
  // compliance
  (45, Icons.description,         'Reports',          'COMPLIANCE'),
  (46, Icons.checklist,           'Frameworks',       'COMPLIANCE'),
  (47, Icons.business,            'Executive',        'COMPLIANCE'),
  (48, Icons.analytics,           'SOC Metrics',      'COMPLIANCE'),
  (49, Icons.crisis_alert,        'Risk Posture',     'COMPLIANCE'),
  // ai
  (50, Icons.smart_toy,           'AI Assistant',     'AI'),
  // system
  (51, Icons.settings,            'Settings',         'SYSTEM'),
  // platform
  (52, Icons.domain,              'Tenants',          'PLATFORM'),
];

class AdminApp extends StatefulWidget {
  final DashboardApi api;
  const AdminApp({super.key, required this.api});
  @override State<AdminApp> createState() => _AdminAppState();
}

class _AdminAppState extends State<AdminApp> {
  int _sel = 0;
  final _scaffoldKey = GlobalKey<ScaffoldState>();

  String get _title => _kSections.firstWhere((s) => s.$1 == _sel).$3;

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
      20 => NetBehaviorScreen(api: api),
      21 => ThreatIntelScreen(api: api),
      22 => SigmaRulesScreen(api: api),
      23 => YaraRulesScreen(api: api),
      24 => JA3Screen(api: api),
      25 => BehavioralScreen(api: api),
      26 => LiveLogsScreen(api: api),
      27 => LogSearchScreen(api: api),
      28 => LogSourcesScreen(api: api),
      29 => ThreatHuntScreen(api: api),
      30 => AlertClustersScreen(api: api),
      31 => CorrelationScreen(api: api),
      32 => SuppressionScreen(api: api),
      33 => CasesScreen(api: api),
      34 => PlaybooksScreen(api: api),
      35 => ApprovalQueueScreen(api: api),
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

  void _nav(int idx) { setState(() => _sel = idx); Navigator.pop(context); }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      key: _scaffoldKey,
      appBar: AppBar(
        title: Text(_title),
        leading: IconButton(icon: const Icon(Icons.menu), onPressed: () => _scaffoldKey.currentState?.openDrawer()),
      ),
      drawer: _Drawer(sel: _sel, onSelect: _nav, onAgentMode: _switchToAgent),
      body: _body(),
    );
  }

  Future<void> _switchToAgent() async {
    await SecureStore.removeApiKey();
    if (!mounted) return;
    Navigator.pushAndRemoveUntil(
      context,
      MaterialPageRoute(builder: (_) => const StatusScreen()),
      (_) => false,
    );
  }
}

// ── Drawer ────────────────────────────────────────────────────────────────────

class _Drawer extends StatefulWidget {
  final int sel;
  final void Function(int) onSelect;
  final VoidCallback onAgentMode;
  const _Drawer({required this.sel, required this.onSelect, required this.onAgentMode});
  @override State<_Drawer> createState() => _DrawerState();
}

class _DrawerState extends State<_Drawer> {
  late String _openGroup;

  static final _groups = <String, List<(int, IconData, String)>>{};
  static final _top    = <(int, IconData, String)>[];
  static bool  _parsed = false;

  static void _parse() {
    if (_parsed) return;
    for (final s in _kSections) {
      if (s.$4.isEmpty) {
        _top.add((s.$1, s.$2, s.$3));
      } else {
        _groups.putIfAbsent(s.$4, () => []).add((s.$1, s.$2, s.$3));
      }
    }
    _parsed = true;
  }

  @override
  void initState() {
    super.initState();
    _parse();
    _openGroup = _groupOf(widget.sel);
  }

  @override
  void didUpdateWidget(_Drawer old) {
    super.didUpdateWidget(old);
    if (old.sel != widget.sel) {
      final g = _groupOf(widget.sel);
      if (g.isNotEmpty && g != _openGroup) setState(() => _openGroup = g);
    }
  }

  String _groupOf(int idx) {
    final s = _kSections.firstWhere((s) => s.$1 == idx, orElse: () => _kSections.first);
    return s.$4;
  }

  void _toggle(String group) =>
      setState(() => _openGroup = _openGroup == group ? '' : group);

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Drawer(
      child: Column(children: [
        // ── Header ─────────────────────────────────────────────────────────
        DrawerHeader(
          margin: EdgeInsets.zero,
          decoration: BoxDecoration(color: cs.primary),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              const Icon(Icons.security, color: Colors.white, size: 28),
              const SizedBox(width: 12),
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisAlignment: MainAxisAlignment.end,
                children: const [
                  Text('XCloak Admin',
                      style: TextStyle(color: Colors.white, fontSize: 16, fontWeight: FontWeight.bold)),
                  SizedBox(height: 2),
                  Text('NGFW Security Suite',
                      style: TextStyle(color: Colors.white70, fontSize: 11)),
                ],
              ),
            ],
          ),
        ),

        // ── Nav list ───────────────────────────────────────────────────────
        Expanded(
          child: ListView(
            padding: const EdgeInsets.only(top: 4, bottom: 8),
            children: [
              for (final t in _top) _tile(context, t.$1, t.$2, t.$3),
              const SizedBox(height: 4),
              for (final entry in _groups.entries) ...[
                _groupHeader(context, entry.key),
                if (_openGroup == entry.key)
                  for (final s in entry.value)
                    _tile(context, s.$1, s.$2, s.$3, indent: true),
              ],
            ],
          ),
        ),

        // ── Footer: back to agent ──────────────────────────────────────────
        const Divider(height: 1),
        Material(
          color: cs.primaryContainer.withOpacity(.35),
          child: ListTile(
            leading: Icon(Icons.phone_android, color: cs.primary, size: 20),
            title: Text('Agent Mode',
                style: TextStyle(color: cs.primary, fontWeight: FontWeight.w600, fontSize: 13)),
            trailing: Icon(Icons.chevron_right, color: cs.primary, size: 18),
            visualDensity: VisualDensity.compact,
            onTap: widget.onAgentMode,
          ),
        ),
        const SizedBox(height: 4),
      ]),
    );
  }

  Widget _groupHeader(BuildContext context, String label) {
    final cs     = Theme.of(context).colorScheme;
    final isOpen = _openGroup == label;
    final hasActive = _groups[label]!.any((s) => s.$1 == widget.sel);
    return InkWell(
      onTap: () => _toggle(label),
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        child: Row(children: [
          if (hasActive)
            Container(width: 3, height: 14, margin: const EdgeInsets.only(right: 8),
                decoration: BoxDecoration(color: cs.primary, borderRadius: BorderRadius.circular(2)))
          else
            const SizedBox(width: 11),
          Text(label,
              style: TextStyle(
                fontSize: 10,
                fontWeight: FontWeight.bold,
                letterSpacing: 1.3,
                color: hasActive ? cs.primary : cs.onSurfaceVariant,
              )),
          const Spacer(),
          Icon(isOpen ? Icons.expand_less : Icons.expand_more,
              size: 16, color: cs.onSurfaceVariant),
        ]),
      ),
    );
  }

  Widget _tile(BuildContext context, int idx, IconData icon, String label, {bool indent = false}) {
    final active = idx == widget.sel;
    final cs     = Theme.of(context).colorScheme;
    return ListTile(
      contentPadding: EdgeInsets.only(left: indent ? 28.0 : 16.0, right: 12.0),
      leading: Icon(icon, size: 17,
          color: active ? cs.primary : cs.onSurfaceVariant),
      title: Text(label,
          style: TextStyle(
            fontSize: 13,
            fontWeight: active ? FontWeight.w600 : FontWeight.normal,
            color: active ? cs.primary : null,
          )),
      selected: active,
      selectedTileColor: cs.primary.withOpacity(.1),
      visualDensity: VisualDensity.compact,
      onTap: () => widget.onSelect(idx),
    );
  }
}
