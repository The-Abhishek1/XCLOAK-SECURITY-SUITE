import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// AD Security — real Active Directory attack/identity/exposure dashboard
// backed by /api/ad/* (api/ad_security_enterprise.go). Was previously showing
// nothing at all: the shared ItdrScreen filtered /api/itdr/findings by
// type='ad', a value that column never actually holds.
// ─────────────────────────────────────────────────────────────────────────────

const _kRed    = Color(0xFFEF4444);
const _kOrange = Color(0xFFF97316);
const _kAmber  = Color(0xFFF59E0B);
const _kBlue   = Color(0xFF3B82F6);
const _kGreen  = Color(0xFF22C55E);
const _kPurple = Color(0xFF8B5CF6);

Color sevColor(String sev) => switch (sev.toLowerCase()) {
  'critical' => _kRed,
  'high'     => _kOrange,
  'medium'   => _kAmber,
  _          => _kBlue,
};

class ADSecurityScreen extends StatefulWidget {
  final DashboardApi api;
  const ADSecurityScreen({super.key, required this.api});
  @override State<ADSecurityScreen> createState() => _ADSecurityState();
}

class _ADSecurityState extends State<ADSecurityScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 14, vsync: this);

  Map<String,dynamic>? _dashboard, _inventory, _identityRisk, _authMonitor, _attacksData,
      _attackPaths, _tiering, _exposure, _threatIntel, _graph, _analytics, _assessment;
  List _gpoChanges = [], _changes = [], _timeline = [];
  bool _loading = true;
  String _identityFilter = '';
  String _attackCategory = '';

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.adDashboard(),
      widget.api.adInventory(),
      widget.api.adIdentityRisk(filter: _identityFilter),
      widget.api.adAuthMonitor(),
      widget.api.adAttacks(category: _attackCategory),
      widget.api.adGPOChanges(),
      widget.api.adChanges(),
      widget.api.adAttackPaths(),
      widget.api.adTiering(),
      widget.api.adExposure(),
      widget.api.adThreatIntel(),
      widget.api.adTimeline(),
      widget.api.adGraph(),
      widget.api.adAnalytics(),
      widget.api.adAssessment(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard    = r[0]  as Map<String,dynamic>?;
      _inventory    = r[1]  as Map<String,dynamic>?;
      _identityRisk = r[2]  as Map<String,dynamic>?;
      _authMonitor  = r[3]  as Map<String,dynamic>?;
      _attacksData  = r[4]  as Map<String,dynamic>?;
      _gpoChanges   = r[5]  as List;
      _changes      = r[6]  as List;
      _attackPaths  = r[7]  as Map<String,dynamic>?;
      _tiering      = r[8]  as Map<String,dynamic>?;
      _exposure     = r[9]  as Map<String,dynamic>?;
      _threatIntel  = r[10] as Map<String,dynamic>?;
      _timeline     = r[11] as List;
      _graph        = r[12] as Map<String,dynamic>?;
      _analytics    = r[13] as Map<String,dynamic>?;
      _assessment   = r[14] as Map<String,dynamic>?;
      _loading      = false;
    });
  }

  Future<void> _reloadIdentity(String filter) async {
    setState(() => _identityFilter = filter);
    final r = await widget.api.adIdentityRisk(filter: filter);
    if (!mounted) return;
    setState(() => _identityRisk = r);
  }

  Future<void> _reloadAttacks(String category) async {
    setState(() => _attackCategory = category);
    final r = await widget.api.adAttacks(category: category);
    if (!mounted) return;
    setState(() => _attacksData = r);
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Inventory'), Tab(text: 'Identity'),
        Tab(text: 'Auth Monitor'), Tab(text: 'Attacks'), Tab(text: 'Changes'),
        Tab(text: 'Attack Paths'), Tab(text: 'Tiering'), Tab(text: 'Exposure'),
        Tab(text: 'Intel'), Tab(text: 'Timeline'), Tab(text: 'Graph'),
        Tab(text: 'Analytics'), Tab(text: 'Assessment'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _inventoryTab(), _identityTab(), _authMonitorTab(), _attacksTab(),
        _changesTab(), _attackPathsTab(), _tieringTab(), _exposureTab(), _intelTab(),
        _timelineTab(), _graphTab(), _analyticsTab(), _assessmentTab(),
      ])),
    ]);
  }

  Widget _overviewTab() {
    final d = _dashboard ?? {};
    final a = _attacksData ?? {};
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Domains', value: str(d['domains'], '0'), color: _kBlue, icon: Icons.domain)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Domain Controllers', value: str(d['domain_controllers'], '0'), color: _kPurple, icon: Icons.dns)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'High-Risk Users', value: str(d['high_risk_users'], '0'), color: _kRed, icon: Icons.person_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Privileged Accounts', value: str(d['privileged_accounts'], '0'), color: _kOrange, icon: Icons.admin_panel_settings)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Active Attacks', value: str(d['active_attacks'], '0'), color: _kRed, icon: Icons.bolt)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'AD Risk Score', value: str(d['ad_risk_score'], '0'), color: _kAmber, icon: Icons.speed)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Domain Trusts', value: str(d['domain_trusts'], '0'), color: _kBlue, icon: Icons.handshake_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Failed Logins (24h)', value: str(d['failed_logins_24h'], '0'), color: _kAmber, icon: Icons.lock_clock)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Attack Breakdown'),
      const SizedBox(height: 8),
      _tile(icon: Icons.key, iconColor: _kOrange, title: 'Kerberoasting', trailing: str(a['kerberoasting'], '0')),
      _tile(icon: Icons.key_outlined, iconColor: _kOrange, title: 'AS-REP Roasting', trailing: str(a['as_rep_roasting'], '0')),
      _tile(icon: Icons.confirmation_number_outlined, iconColor: _kRed, title: 'Golden Ticket', trailing: str(a['golden_ticket'], '0')),
      _tile(icon: Icons.password, iconColor: _kRed, title: 'Pass-the-Hash', trailing: str(a['pass_the_hash'], '0')),
      _tile(icon: Icons.sync_problem, iconColor: _kRed, title: 'DCSync', trailing: str(a['dcsync'], '0')),
      _tile(icon: Icons.dns_outlined, iconColor: _kRed, title: 'DCShadow', trailing: str(a['dcshadow'], '0')),
      _tile(icon: Icons.swap_horiz, iconColor: _kAmber, title: 'Lateral Movement', trailing: str(a['lateral_movement'], '0')),
      _tile(icon: Icons.trending_up, iconColor: _kAmber, title: 'Priv Escalation', trailing: str(a['priv_escalation'], '0')),
      if (_assessment != null) ...[
        const SizedBox(height: 16),
        SectionTitle('Security Assessment'),
        const SizedBox(height: 8),
        _scoreBar((_assessment!['overall_score'] as num?)?.toDouble() ?? 0),
      ],
    ]));
  }

  Widget _scoreBar(double score) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
      color: Theme.of(context).colorScheme.surfaceContainerLow),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Row(children: [
        const Expanded(child: Text('Overall Score', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
        Text('${score.toStringAsFixed(0)}%', style: TextStyle(fontWeight: FontWeight.w800,
          color: score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed)),
      ]),
      const SizedBox(height: 8),
      ClipRRect(borderRadius: BorderRadius.circular(4), child: LinearProgressIndicator(
        value: score / 100, minHeight: 6,
        backgroundColor: _kRed.withValues(alpha: .15),
        valueColor: AlwaysStoppedAnimation(score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed))),
    ]),
  );

  Widget _inventoryTab() {
    final inv = _inventory ?? {};
    final domainList = (inv['domain_list'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Forests', value: str(inv['forests'], '0'), color: _kBlue, icon: Icons.forest_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Domains', value: str(inv['domains'], '0'), color: _kBlue, icon: Icons.domain)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Domain Controllers', value: str(inv['domain_controllers'], '0'), color: _kPurple, icon: Icons.dns)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Users', value: str(inv['users'], '0'), color: _kGreen, icon: Icons.people_outline)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Computers', value: str(inv['computers'], '0'), color: _kBlue, icon: Icons.computer)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'GPOs', value: str(inv['gpos'], '0'), color: _kAmber, icon: Icons.policy_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Service Accounts', value: str(inv['service_accounts'], '0'), color: _kAmber, icon: Icons.smart_toy_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Admin Accounts', value: str(inv['admin_accounts'], '0'), color: _kOrange, icon: Icons.admin_panel_settings)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Domains'),
      const SizedBox(height: 8),
      if (domainList.isEmpty) const XEmptyState('No AD domains discovered', icon: Icons.domain_disabled_outlined)
      else ...domainList.map((dm) {
        final m = dm as Map<String,dynamic>;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text('risk ${str(m['risk_score'], '0')}', style: TextStyle(fontWeight: FontWeight.w800,
                color: (m['risk_score'] as int? ?? 0) > 70 ? _kRed : _kAmber)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['netbios'])} · ${str(m['functional_level'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 4),
            Text('${str(m['dc_count'],'0')} DCs · ${str(m['user_count'],'0')} users · ${str(m['group_count'],'0')} groups · '
                 '${str(m['computer_count'],'0')} computers · ${str(m['gpo_count'],'0')} GPOs · ${str(m['trust_count'],'0')} trusts',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ]),
        );
      }),
    ]));
  }

  static const _identityFilters = [
    ['', 'All'], ['high_risk', 'High Risk'], ['dormant', 'Dormant'], ['admin', 'Admin'],
    ['service_accounts', 'Service'], ['password_never_expires', 'No PW Expiry'], ['stale', 'Stale'],
  ];

  Widget _identityTab() {
    final ir = _identityRisk ?? {};
    final users = (ir['users'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SizedBox(
        height: 34,
        child: ListView(scrollDirection: Axis.horizontal, children: _identityFilters.map((f) {
          final selected = _identityFilter == f[0];
          return Padding(
            padding: const EdgeInsets.only(right: 6),
            child: ChoiceChip(
              label: Text(f[1], style: const TextStyle(fontSize: 11)),
              selected: selected,
              onSelected: (_) => _reloadIdentity(f[0]),
            ),
          );
        }).toList()),
      ),
      const SizedBox(height: 12),
      Row(children: [
        Expanded(child: KpiCard(label: 'High Risk', value: str(ir['high_risk'], '0'), color: _kRed, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Dormant', value: str(ir['dormant'], '0'), color: Colors.grey, icon: Icons.person_off)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'No PW Expiry', value: str(ir['password_never_expires'], '0'), color: _kAmber, icon: Icons.password)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Admins', value: str(ir['admin_accounts'], '0'), color: _kOrange, icon: Icons.admin_panel_settings)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Users'),
      const SizedBox(height: 8),
      if (users.isEmpty) const XEmptyState('No AD users found', icon: Icons.people_outline)
      else ...users.map((u) {
        final m = u as Map<String,dynamic>;
        final risk = (m['risk_score'] as int?) ?? 0;
        final sam = str(m['sam_account']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: (risk > 70 ? _kRed : Theme.of(context).colorScheme.outlineVariant).withValues(alpha: .3)),
            color: risk > 70 ? _kRed.withValues(alpha: .04) : null),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['display_name'], sam), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text('risk $risk', style: TextStyle(fontWeight: FontWeight.w800, color: risk > 70 ? _kRed : _kAmber)),
            ]),
            const SizedBox(height: 2),
            Text('$sam · ${str(m['department'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 6),
            Wrap(spacing: 4, runSpacing: 4, children: [
              if (m['is_admin'] == true) const _Pill(label: 'ADMIN', color: _kOrange),
              if (m['is_service_account'] == true) const _Pill(label: 'SERVICE', color: _kPurple),
              if (m['password_never_expires'] == true) const _Pill(label: 'NO PW EXPIRY', color: _kAmber),
              if (m['is_enabled'] != true) const _Pill(label: 'DISABLED', color: Colors.grey),
            ]),
            const SizedBox(height: 6),
            Row(children: [
              TextButton(
                onPressed: () => _respond(m['is_service_account'] == true ? 'disable_service_account' : 'disable_user', sam),
                child: const Text('Disable', style: TextStyle(fontSize: 11)),
              ),
              TextButton(
                onPressed: () => _respond('reset_password', sam),
                child: const Text('Reset Password', style: TextStyle(fontSize: 11)),
              ),
              if (m['is_admin'] == true)
                TextButton(
                  onPressed: () => _respond('remove_group_membership', sam),
                  child: const Text('Remove Admin', style: TextStyle(fontSize: 11)),
                ),
            ]),
          ]),
        );
      }),
    ]));
  }

  Widget _authMonitorTab() {
    final am = _authMonitor ?? {};
    final events = (am['events'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Failed Logins', value: str(am['failed_logins'], '0'), color: _kAmber, icon: Icons.lock_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Password Spray', value: str(am['password_spray'], '0'), color: _kRed, icon: Icons.grain)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Brute Force', value: str(am['brute_force'], '0'), color: _kRed, icon: Icons.gpp_bad_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Suspicious Logons', value: str(am['suspicious_logons'], '0'), color: _kOrange, icon: Icons.visibility_outlined)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Auth Events'),
      const SizedBox(height: 8),
      if (events.isEmpty) const XEmptyState('No authentication events recorded', icon: Icons.verified_user_outlined)
      else ...events.map((e) {
        final m = e as Map<String,dynamic>;
        return _tile(
          icon: Icons.login, iconColor: sevColor(str(m['severity'])),
          title: str(m['event_type']).replaceAll('_', ' '),
          subtitle: '${str(m['source_user'])} · ${str(m['source_computer'])} · ${str(m['source_ip'])} · ${str(m['auth_type'])}',
          trailing: timeAgo(m['created_at']),
        );
      }),
    ]));
  }

  static const _attackCategories = [
    ['', 'All'], ['kerberos', 'Kerberos'], ['credential', 'Credential'],
    ['privilege', 'Privilege'], ['lateral', 'Lateral'],
  ];

  Widget _attacksTab() {
    final ad = _attacksData ?? {};
    final attacks = (ad['attacks'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SizedBox(
        height: 34,
        child: ListView(scrollDirection: Axis.horizontal, children: _attackCategories.map((f) {
          final selected = _attackCategory == f[0];
          return Padding(
            padding: const EdgeInsets.only(right: 6),
            child: ChoiceChip(
              label: Text(f[1], style: const TextStyle(fontSize: 11)),
              selected: selected,
              onSelected: (_) => _reloadAttacks(f[0]),
            ),
          );
        }).toList()),
      ),
      const SizedBox(height: 12),
      Row(children: [
        Expanded(child: KpiCard(label: 'Kerberoasting', value: str(ad['kerberoasting'], '0'), color: _kOrange, icon: Icons.key)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Pass-the-Hash', value: str(ad['pass_the_hash'], '0'), color: _kRed, icon: Icons.password)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'DCSync', value: str(ad['dcsync'], '0'), color: _kRed, icon: Icons.sync_problem)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Priv Escalation', value: str(ad['priv_escalation'], '0'), color: _kAmber, icon: Icons.trending_up)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Attacks'),
      const SizedBox(height: 8),
      if (attacks.isEmpty) const XEmptyState('No AD attacks detected', icon: Icons.verified_user_outlined)
      else ...attacks.map((a0) {
        final m = a0 as Map<String,dynamic>;
        final sev = str(m['severity']);
        final sourceUser = str(m['source_user']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['attack_type']).replaceAll('_', ' '),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['source_user'])} · ${str(m['source_computer'])} · ${str(m['source_ip'])} → ${str(m['target'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['technique']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(m['technique']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            if (str(m['mitre_technique']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('MITRE ${str(m['mitre_technique'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
            ],
            const SizedBox(height: 8),
            Row(children: [
              TextButton(
                onPressed: sourceUser == '—' ? null : () => _respond('disable_user', sourceUser),
                child: const Text('Disable User', style: TextStyle(fontSize: 11)),
              ),
              TextButton(
                onPressed: sourceUser == '—' ? null : () => _respond('reset_password', sourceUser),
                child: const Text('Reset Password', style: TextStyle(fontSize: 11)),
              ),
            ]),
          ]),
        );
      }),
    ]));
  }

  Future<void> _respond(String action, String target) async {
    final res = await widget.api.adRespond({'action': action, 'target': target});
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  Widget _changesTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('GPO Changes'),
      const SizedBox(height: 8),
      if (_gpoChanges.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No GPO changes recorded', style: TextStyle(color: Colors.grey)))
      else ..._gpoChanges.map((g) {
        final m = g as Map<String,dynamic>;
        return _tile(icon: Icons.policy_outlined, title: str(m['name']),
          subtitle: '${str(m['status'])} · ${str(m['linked_ous'])}', trailing: timeAgo(m['last_modified']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Directory Changes'),
      const SizedBox(height: 8),
      if (_changes.isEmpty) const XEmptyState('No directory changes recorded', icon: Icons.history_outlined)
      else ..._changes.map((c) {
        final m = c as Map<String,dynamic>;
        return _tile(
          icon: Icons.edit_note, iconColor: sevColor(str(m['severity'])),
          title: str(m['event_type']).replaceAll('_', ' '),
          subtitle: '${str(m['source_user'])} · ${str(m['source_computer'])} → ${str(m['target'])}',
          trailing: timeAgo(m['created_at']),
        );
      }),
    ]));
  }

  Widget _attackPathsTab() {
    final identities = (_attackPaths?['risk_identities'] as List?) ?? [];
    final computers  = (_attackPaths?['risk_computers'] as List?) ?? [];
    if (identities.isEmpty && computers.isEmpty) {
      return const XEmptyState('No attack paths found', icon: Icons.route_outlined);
    }
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('High-Risk Identities'),
      const SizedBox(height: 8),
      if (identities.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No privileged/service identities flagged', style: TextStyle(color: Colors.grey)))
      else ...identities.map((i) {
        final m = i as Map<String,dynamic>;
        return _tile(
          icon: Icons.person_outline, iconColor: _kOrange,
          title: str(m['display_name'], str(m['sam_account'])),
          subtitle: [
            if (m['is_admin'] == true) 'Admin',
            if (m['is_service_account'] == true) 'Service Account',
          ].join(' · '),
          trailing: 'risk ${str(m['risk_score'], '0')}',
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Computers with Unconstrained Delegation'),
      const SizedBox(height: 8),
      if (computers.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No computers with unconstrained delegation', style: TextStyle(color: Colors.grey)))
      else ...computers.map((c) {
        final m = c as Map<String,dynamic>;
        return _tile(icon: Icons.computer, iconColor: _kRed, title: str(m['name']),
          trailing: 'risk ${str(m['risk_score'], '0')}');
      }),
    ]));
  }

  Widget _tieringTab() {
    final tier0 = (_tiering?['tier0_assets'] as List?) ?? [];
    final tier1 = (_tiering?['tier1_assets'] as List?) ?? [];
    final tier2 = (_tiering?['tier2_assets'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Tier 0 — Domain Controllers'),
      const SizedBox(height: 8),
      ...tier0.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.security, iconColor: _kRed, title: str(m['name']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Tier 1 — Server Admins'),
      const SizedBox(height: 8),
      ...tier1.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.admin_panel_settings, iconColor: _kOrange, title: str(m['name']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Tier 2 — Workstations & Standard Users'),
      const SizedBox(height: 8),
      ...tier2.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.desktop_windows_outlined, iconColor: _kBlue, title: str(m['name']), trailing: str(m['count']));
      }),
    ]));
  }

  Widget _exposureTab() {
    final ex = _exposure ?? {};
    final findings = (ex['findings'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      KpiCard(label: 'Unconstrained Delegation', value: str(ex['unconstrained_delegation'], '0'), color: _kRed, icon: Icons.warning_amber),
      const SizedBox(height: 16),
      SectionTitle('Findings'),
      const SizedBox(height: 8),
      if (findings.isEmpty) const XEmptyState('No exposure findings', icon: Icons.shield_outlined)
      else ...findings.map((f) {
        final m = f as Map<String,dynamic>;
        final sev = str(m['severity']);
        final affected = ((m['affected'] as List?) ?? []).map((e) => e.toString()).join(', ');
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['type']).replaceAll('_', ' '),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text(str(m['description']), style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            if (affected.isNotEmpty) ...[
              const SizedBox(height: 6),
              Text('Affected: $affected', style: const TextStyle(fontSize: 11), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
          ]),
        );
      }),
    ]));
  }

  Widget _intelTab() {
    final iocs = (_threatIntel?['ioc_matches'] as List?) ?? [];
    if (iocs.isEmpty) return const XEmptyState('No IOC matches observed', icon: Icons.travel_explore_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('IOC Matches'),
      const SizedBox(height: 8),
      ...iocs.map((i) {
        final m = i as Map<String,dynamic>;
        return _tile(icon: Icons.fingerprint, title: str(m['value']),
          subtitle: str(m['type']).toUpperCase(), trailing: '${str(m['hits'])} hits');
      }),
    ]));
  }

  Widget _timelineTab() {
    if (_timeline.isEmpty) return const XEmptyState('No AD events recorded', icon: Icons.history_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _timeline.length,
      itemBuilder: (_, i) {
        final m = _timeline[i] as Map<String,dynamic>;
        return _tile(
          icon: Icons.circle_notifications_outlined, iconColor: sevColor(str(m['severity'])),
          title: str(m['event_type']).replaceAll('_', ' '),
          subtitle: '${str(m['source_user'])} · ${str(m['source_computer'])} → ${str(m['target'])}',
          trailing: timeAgo(m['created_at']),
        );
      },
    ));
  }

  Widget _graphTab() {
    final nodes = (_graph?['nodes'] as List?) ?? [];
    final edges = (_graph?['edges'] as List?) ?? [];
    final stats = (_graph?['stats'] as Map?) ?? {};
    if (nodes.isEmpty) return const XEmptyState('No AD relationship graph data', icon: Icons.hub_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Users', value: str(stats['users'], '0'), color: _kGreen, icon: Icons.people_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Computers', value: str(stats['computers'], '0'), color: _kBlue, icon: Icons.computer)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'DCs', value: str(stats['dcs'], '0'), color: _kPurple, icon: Icons.dns)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Edges', value: '${edges.length}', color: _kRed, icon: Icons.call_split)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Relationships'),
      const SizedBox(height: 8),
      ...edges.map((e) {
        final m = e as Map<String,dynamic>;
        final risk = str(m['risk'], 'medium');
        return _tile(
          icon: Icons.arrow_forward, iconColor: sevColor(risk),
          title: '${str(m['source'])} → ${str(m['target'])}',
          subtitle: str(m['label']),
          trailing: risk.toUpperCase(),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Nodes'),
      const SizedBox(height: 8),
      ...nodes.map((n) {
        final m = n as Map<String,dynamic>;
        return _tile(icon: Icons.circle, iconColor: _kBlue, title: str(m['label']),
          subtitle: str(m['type']).replaceAll('_', ' '), trailing: 'risk ${str(m['risk'], '0')}');
      }),
    ]));
  }

  Widget _analyticsTab() {
    final a = _analytics ?? {};
    final breakdown = (a['attack_breakdown'] as List?) ?? [];
    final topFailed = (a['top_failed_logins'] as List?) ?? [];
    final trend = (a['auth_trend'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Attacks', value: str(a['total_attacks'], '0'), color: _kRed, icon: Icons.bolt)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'New Admins (7d)', value: str(a['new_admins_7d'], '0'), color: _kOrange, icon: Icons.person_add_alt)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Attack Breakdown'),
      const SizedBox(height: 8),
      ...breakdown.map((b) {
        final m = b as Map<String,dynamic>;
        return _tile(icon: Icons.category_outlined, title: str(m['type']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Top Failed Logins'),
      const SizedBox(height: 8),
      if (topFailed.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No repeat failed-login offenders', style: TextStyle(color: Colors.grey)))
      else ...topFailed.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.person_off_outlined, title: str(m['user']),
          subtitle: str(m['source_ip']), trailing: '${str(m['count'])} fails');
      }),
      if (trend.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Auth Events (14 days)'),
        const SizedBox(height: 8),
        ...trend.map((t) {
          final m = t as Map<String,dynamic>;
          return _tile(icon: Icons.calendar_today_outlined, title: str(m['date']), trailing: str(m['count'], '0'));
        }),
      ],
    ]));
  }

  Widget _assessmentTab() {
    final checks = (_assessment?['checks'] as List?) ?? [];
    final score = (_assessment?['overall_score'] as num?)?.toDouble() ?? 0;
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      _scoreBar(score),
      const SizedBox(height: 16),
      SectionTitle('Checks'),
      const SizedBox(height: 8),
      if (checks.isEmpty) const XEmptyState('No assessment checks available', icon: Icons.checklist_outlined)
      else ...checks.map((c) {
        final m = c as Map<String,dynamic>;
        final pass = str(m['status']) == 'pass';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: (pass ? _kGreen : sevColor(str(m['severity']))).withValues(alpha: .3)),
            color: (pass ? _kGreen : sevColor(str(m['severity']))).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['title']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: pass ? 'PASS' : 'FAIL', color: pass ? _kGreen : sevColor(str(m['severity']))),
            ]),
            const SizedBox(height: 4),
            Text(str(m['detail']), style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            if (!pass && str(m['remediation']).isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(str(m['remediation']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
          ]),
        );
      }),
    ]));
  }

  Widget _tile({required IconData icon, Color? iconColor, required String title, String? subtitle, String? trailing}) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
        color: Theme.of(context).colorScheme.surfaceContainerLow),
      child: Row(children: [
        Icon(icon, size: 16, color: iconColor ?? Colors.grey),
        const SizedBox(width: 10),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600),
            maxLines: 1, overflow: TextOverflow.ellipsis),
          if (subtitle != null && subtitle.isNotEmpty)
            Text(subtitle, style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 1, overflow: TextOverflow.ellipsis),
        ])),
        if (trailing != null) Text(trailing, style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
      ]),
    );
  }
}

class _Pill extends StatelessWidget {
  final String label;
  final Color color;
  const _Pill({required this.label, required this.color});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
    decoration: BoxDecoration(color: color.withValues(alpha: .12), borderRadius: BorderRadius.circular(5)),
    child: Text(label, style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: color)),
  );
}
