import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Defense Evasion — real MITRE ATT&CK TA0005 dashboard backed by /api/de/*
// (api/defense_evasion_enterprise.go). This was one of 8 "Cloud & Infra" tabs
// previously showing nothing at all: the shared ItdrScreen filtered
// /api/itdr/findings?type=defense_evasion, a value itdr_findings.finding_type
// never actually holds (it's only ever brute_force/credential_theft/mfa_gap
// etc.), so the query always matched zero rows. This category has its own
// real, much richer backend that was never wired to mobile at all.
// ─────────────────────────────────────────────────────────────────────────────

const _kRed    = Color(0xFFEF4444);
const _kOrange = Color(0xFFF97316);
const _kAmber  = Color(0xFFF59E0B);
const _kBlue   = Color(0xFF3B82F6);
const _kGreen  = Color(0xFF22C55E);
const _kPurple = Color(0xFF8B5CF6);

class DefenseEvasionScreen extends StatefulWidget {
  final DashboardApi api;
  const DefenseEvasionScreen({super.key, required this.api});
  @override State<DefenseEvasionScreen> createState() => _DefenseEvasionState();
}

class _DefenseEvasionState extends State<DefenseEvasionScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 9, vsync: this);

  Map<String,dynamic>? _dashboard, _controls, _tamper, _behavioral, _mitre, _threatIntel, _analytics;
  List _logEvasion = [], _evasionEvents = [], _correlation = [];
  String _eventsCategory = '';
  bool _loading = true;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.deDashboard(),
      widget.api.deControls(),
      widget.api.deTamper(),
      widget.api.deLogEvasion(),
      widget.api.deEvasionEvents(category: _eventsCategory),
      widget.api.deBehavioral(),
      widget.api.deCorrelation(),
      widget.api.deMITRE(),
      widget.api.deThreatIntel(),
      widget.api.deAnalytics(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard    = r[0] as Map<String,dynamic>?;
      _controls     = r[1] as Map<String,dynamic>?;
      _tamper       = r[2] as Map<String,dynamic>?;
      _logEvasion   = r[3] as List;
      _evasionEvents= r[4] as List;
      _behavioral   = r[5] as Map<String,dynamic>?;
      _correlation  = r[6] as List;
      _mitre        = r[7] as Map<String,dynamic>?;
      _threatIntel  = r[8] as Map<String,dynamic>?;
      _analytics    = r[9] as Map<String,dynamic>?;
      _loading      = false;
    });
  }

  Future<void> _loadEvents(String category) async {
    setState(() => _eventsCategory = category);
    final list = await widget.api.deEvasionEvents(category: category);
    if (!mounted) return;
    setState(() => _evasionEvents = list);
  }

  Future<void> _respond(String action, {String hostname = '', String target = '', String reason = ''}) async {
    final res = await widget.api.deRespond({
      'action': action, 'hostname': hostname, 'target': target, 'reason': reason,
    });
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  Future<void> _remediateControl(Map<String,dynamic> m) async {
    final name = str(m['control_name']).toLowerCase();
    final action = name.contains('defender') ? 'reenable_defender'
                 : name.contains('firewall') ? 'restore_firewall'
                 : 'restart_security_services';
    await _respond(action, hostname: str(m['hostname'], ''));
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Controls'), Tab(text: 'Tamper'),
        Tab(text: 'Events'), Tab(text: 'Behavioral'), Tab(text: 'Correlation'),
        Tab(text: 'MITRE'), Tab(text: 'Intelligence'), Tab(text: 'Analytics'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _controlsTab(), _tamperTab(), _eventsTab(), _behavioralTab(),
        _correlationTab(), _mitreTab(), _intelTab(), _analyticsTab(),
      ])),
    ]);
  }

  Widget _overviewTab() {
    final d = _dashboard ?? {};
    final categories = (d['top_categories'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Open Alerts', value: str(d['defense_evasion_alerts'], '0'), color: _kRed, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Active (24h)', value: str(d['active_evasion_attempts'], '0'), color: _kOrange, icon: Icons.bolt)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Disabled Controls', value: str(d['disabled_security_controls'], '0'), color: _kRed, icon: Icons.security)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Tamper Events', value: str(d['tamper_events'], '0'), color: _kOrange, icon: Icons.report_problem_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'AMSI Bypasses', value: str(d['amsi_bypass_attempts'], '0'), color: _kPurple, icon: Icons.code)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'High-Risk Hosts', value: str(d['high_risk_hosts'], '0'), color: _kAmber, icon: Icons.computer)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'MITRE Coverage', value: '${str(d['mitre_coverage'], '0')}%', color: _kGreen, icon: Icons.verified_user)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Top Categories'),
      const SizedBox(height: 8),
      if (categories.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No categories reported', style: TextStyle(color: Colors.grey)))
      else ...categories.map((c) => _tile(icon: Icons.category_outlined, title: str(c))),
    ]));
  }

  Widget _controlsTab() {
    final d = _controls ?? {};
    final controls = (d['controls'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Active', value: str(d['active'], '0'), color: _kGreen, icon: Icons.check_circle_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Degraded', value: str(d['degraded'], '0'), color: _kAmber, icon: Icons.warning_amber)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Disabled', value: str(d['disabled'], '0'), color: _kRed, icon: Icons.cancel_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Total', value: '${controls.length}', color: _kBlue, icon: Icons.security)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Security Controls'),
      const SizedBox(height: 8),
      if (controls.isEmpty) const XEmptyState('No security controls reported', icon: Icons.security)
      else ...controls.map((c0) {
        final m = c0 as Map<String,dynamic>;
        final tampered = m['tampered'] == true;
        final status = str(m['status']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: tampered ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: tampered ? _kRed.withValues(alpha: .04) : null),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['control_name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              if (tampered) const Padding(padding: EdgeInsets.only(right: 6), child: _Pill(label: 'TAMPERED', color: _kRed)),
              StatusChip(status),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['control_type'])} · ${str(m['hostname'])} · v${str(m['version'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            Text('Last check: ${timeAgo(m['last_check'])}', style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            if (tampered) ...[
              const SizedBox(height: 8),
              Align(alignment: Alignment.centerRight, child: TextButton(
                onPressed: () => _remediateControl(m),
                child: const Text('Remediate', style: TextStyle(fontSize: 11)),
              )),
            ],
          ]),
        );
      }),
    ]));
  }

  Widget _tamperTab() {
    final d = _tamper ?? {};
    final events = (d['events'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Tamper Events', value: str(d['total'], '0'), color: _kRed, icon: Icons.report_problem_outlined)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Tamper Events'),
      const SizedBox(height: 8),
      if (events.isEmpty) const XEmptyState('No security-control tampering detected', icon: Icons.shield_outlined)
      else ...events.map((e0) {
        final m = e0 as Map<String,dynamic>;
        final sev = str(m['severity']);
        final actorPid = (m['actor_pid'] as num?)?.toInt() ?? 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['action']).replaceAll('_', ' '), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              SevChip(sev),
            ]),
            const SizedBox(height: 4),
            Text('Target: ${str(m['target'])} · ${str(m['hostname'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            Text('Actor: ${str(m['actor_name'])} (pid ${actorPid}) · MITRE ${str(m['mitre_id'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 8),
            Wrap(spacing: 4, children: [
              TextButton(
                onPressed: () => _respond('isolate_endpoint', hostname: str(m['hostname'], ''),
                  reason: 'Tamper: ${str(m['action'])} on ${str(m['target'])}'),
                child: const Text('Isolate Host', style: TextStyle(fontSize: 11))),
              if (actorPid > 0)
                TextButton(
                  onPressed: () => _respond('kill_process', hostname: str(m['hostname'], ''), target: '$actorPid',
                    reason: 'Tamper: ${str(m['action'])} on ${str(m['target'])}'),
                  child: const Text('Kill Actor Process', style: TextStyle(fontSize: 11))),
              TextButton(
                onPressed: () => _respond('create_incident', hostname: str(m['hostname']),
                  target: str(m['target']), reason: str(m['action'])),
                child: const Text('Escalate', style: TextStyle(fontSize: 11))),
            ]),
          ]),
        );
      }),
    ]));
  }

  Widget _eventsTab() {
    // Must match the real de_events.category values the backend actually
    // writes (see cmd/seed/demo/main.go's seedDefenseEvasion) — the previous
    // list ('process'/'file'/'persistence'/'container' etc.) never matched
    // any real row, so every filter chip except "All" silently returned zero
    // events, the same wrong-taxonomy bug class this whole nav group was
    // rebuilt to get away from.
    const categories = ['', 'log_evasion', 'process_evasion', 'script_evasion', 'credential_bypass', 'network_evasion'];
    const labels = {
      '': 'All', 'log_evasion': 'Log', 'process_evasion': 'Process', 'script_evasion': 'Script',
      'credential_bypass': 'Credential', 'network_evasion': 'Network',
    };
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Log Evasion'),
      const SizedBox(height: 8),
      if (_logEvasion.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No log-evasion attempts observed', style: TextStyle(color: Colors.grey)))
      else ..._logEvasion.map((e0) => _eventTile(e0 as Map<String,dynamic>)),
      const SizedBox(height: 16),
      SectionTitle('All Evasion Events'),
      const SizedBox(height: 8),
      SizedBox(
        height: 34,
        child: ListView(scrollDirection: Axis.horizontal, children: categories.map((c) {
          final selected = c == _eventsCategory;
          return Padding(
            padding: const EdgeInsets.only(right: 6),
            child: ChoiceChip(
              label: Text(labels[c]!, style: const TextStyle(fontSize: 11)),
              selected: selected,
              onSelected: (_) => _loadEvents(c),
            ),
          );
        }).toList()),
      ),
      const SizedBox(height: 8),
      if (_evasionEvents.isEmpty) const XEmptyState('No evasion events in this category', icon: Icons.visibility_off_outlined)
      else ..._evasionEvents.map((e0) => _eventTile(e0 as Map<String,dynamic>)),
    ]));
  }

  Widget _eventTile(Map<String,dynamic> m) {
    final sev = str(m['severity']);
    return Container(
      margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(borderRadius: BorderRadius.circular(10), color: Theme.of(context).colorScheme.surfaceContainerLow),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(children: [
          Expanded(child: Text(str(m['technique']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
          SevChip(sev),
        ]),
        if (str(m['description']).isNotEmpty) ...[
          const SizedBox(height: 4),
          Text(str(m['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
        ],
        const SizedBox(height: 4),
        Text('${str(m['hostname'])} · ${str(m['process_name'])} · ${str(m['user_name'])}',
          style: const TextStyle(fontSize: 11, color: Colors.grey)),
        if (str(m['cmdline']).isNotEmpty) ...[
          const SizedBox(height: 2),
          Text(str(m['cmdline']), style: const TextStyle(fontSize: 10.5, color: Colors.grey, fontFamily: 'monospace'),
            maxLines: 1, overflow: TextOverflow.ellipsis),
        ],
        const SizedBox(height: 4),
        Row(children: [
          Text('MITRE ${str(m['mitre_id'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
          const Spacer(),
          Text(timeAgo(m['created_at']), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
        ]),
      ]),
    );
  }

  Widget _behavioralTab() {
    final detections = (_behavioral?['detections'] as List?) ?? [];
    if (detections.isEmpty) return const XEmptyState('No behavioral evasion detections', icon: Icons.psychology_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: detections.length,
      itemBuilder: (_, i) {
        final m = detections[i] as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['rule']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              SevChip(sev),
            ]),
            if (str(m['description']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(m['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 4),
            Text('${str(m['hostname'])} · ${str(m['process'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['cmdline']).isNotEmpty) ...[
              const SizedBox(height: 2),
              Text(str(m['cmdline']), style: const TextStyle(fontSize: 10.5, color: Colors.grey, fontFamily: 'monospace'),
                maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 4),
            Text('MITRE ${str(m['mitre'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
          ]),
        );
      },
    ));
  }

  Widget _correlationTab() {
    if (_correlation.isEmpty) return const XEmptyState('No correlated evasion incidents', icon: Icons.hub_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _correlation.length,
      itemBuilder: (_, i) {
        final m = _correlation[i] as Map<String,dynamic>;
        final sev = str(m['severity']);
        final techniques = str(m['techniques']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['title']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              SevChip(sev),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['incident_id'])} · ${str(m['hostname'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (techniques.isNotEmpty && techniques != '—') ...[
              const SizedBox(height: 4),
              Text('Techniques: $techniques', style: const TextStyle(fontSize: 11, color: _kPurple)),
            ],
            const SizedBox(height: 8),
            Row(children: [
              StatusChip(str(m['status'])),
              const Spacer(),
              TextButton(
                onPressed: () => _respond('create_incident', hostname: str(m['hostname']),
                  target: str(m['incident_id']), reason: str(m['title'])),
                child: const Text('Escalate', style: TextStyle(fontSize: 11))),
            ]),
          ]),
        );
      },
    ));
  }

  Widget _mitreTab() {
    final tactic = (_mitre?['tactic'] as Map?) ?? {};
    final techniques = (_mitre?['techniques'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Container(
        padding: const EdgeInsets.all(12),
        decoration: BoxDecoration(borderRadius: BorderRadius.circular(10), color: _kPurple.withValues(alpha: .08)),
        child: Row(children: [
          const Icon(Icons.hub, size: 18, color: _kPurple),
          const SizedBox(width: 10),
          Expanded(child: Text('${str(tactic['id'])} · ${str(tactic['name'])}',
            style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
        ]),
      ),
      const SizedBox(height: 16),
      SectionTitle('Techniques'),
      const SizedBox(height: 8),
      if (techniques.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No MITRE technique data yet', style: TextStyle(color: Colors.grey)))
      else ...techniques.map((t0) {
        final m = t0 as Map<String,dynamic>;
        final detected = m['detected'] == true;
        final subs = (m['sub_techniques'] as List?) ?? [];
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: detected ? sevColor(sev).withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: detected ? sevColor(sev).withValues(alpha: .05) : null),
          child: ExpansionTile(
            tilePadding: const EdgeInsets.symmetric(horizontal: 12),
            title: Text('${str(m['id'])} — ${str(m['name'])}', style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700)),
            subtitle: Text('${str(m['count'], '0')} events observed', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            trailing: detected ? SevChip(sev) : const _Pill(label: 'CLEAN', color: Color(0xFF6B7280)),
            children: subs.isEmpty
              ? [const Padding(padding: EdgeInsets.only(bottom: 8),
                  child: Text('No sub-techniques tracked', style: TextStyle(fontSize: 11, color: Colors.grey)))]
              : subs.map((s0) {
                  final s = s0 as Map<String,dynamic>;
                  final sDetected = s['detected'] == true;
                  return ListTile(
                    dense: true,
                    title: Text('${str(s['id'])} — ${str(s['name'])}', style: const TextStyle(fontSize: 12)),
                    trailing: Text('${str(s['count'], '0')}', style: TextStyle(fontSize: 11, color: sDetected ? _kRed : Colors.grey)),
                  );
                }).toList(),
          ),
        );
      }),
    ]));
  }

  Widget _intelTab() {
    final techniques = (_threatIntel?['observed_techniques'] as List?) ?? [];
    if (techniques.isEmpty) return const XEmptyState('No technique frequency data yet', icon: Icons.insights_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Observed Techniques'),
      const SizedBox(height: 8),
      ...techniques.map((t0) {
        final m = t0 as Map<String,dynamic>;
        return _tile(icon: Icons.category_outlined, iconColor: sevColor(str(m['severity'])),
          title: str(m['technique']), trailing: '${str(m['count'])}× · ${str(m['severity']).toUpperCase()}');
      }),
    ]));
  }

  Widget _analyticsTab() {
    final a = _analytics ?? {};
    final trend = (a['evasion_trend'] as List?) ?? [];
    final topTech = (a['top_techniques'] as List?) ?? [];
    final endpoints = (a['most_targeted_endpoints'] as List?) ?? [];
    final controlStatus = (a['control_status'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'MITRE Coverage', value: '${str(a['mitre_coverage'], '0')}%', color: _kGreen, icon: Icons.verified_user)),
      ]),
      if (trend.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Evasion Events — 14 Day Trend'),
        const SizedBox(height: 8),
        _TrendBar(
          values: trend.map((t) => ((t as Map)['count'] as num?)?.toInt() ?? 0).toList(),
          labels: trend.map((t) { final d = str((t as Map)['date']); return d.length >= 10 ? d.substring(8, 10) : d; }).toList(),
        ),
      ],
      const SizedBox(height: 16),
      SectionTitle('Top Techniques'),
      const SizedBox(height: 8),
      if (topTech.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No technique data yet', style: TextStyle(color: Colors.grey)))
      else ...topTech.map((t0) {
        final m = t0 as Map<String,dynamic>;
        return _tile(icon: Icons.bar_chart, iconColor: sevColor(str(m['severity'])), title: str(m['technique']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Most Targeted Endpoints'),
      const SizedBox(height: 8),
      if (endpoints.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No endpoint data yet', style: TextStyle(color: Colors.grey)))
      else ...endpoints.map((e0) {
        final m = e0 as Map<String,dynamic>;
        return _tile(icon: Icons.computer, title: str(m['hostname']),
          subtitle: '${str(m['event_count'], '0')} events', trailing: '${str(m['risk'], '0')}% critical');
      }),
      const SizedBox(height: 16),
      SectionTitle('Control Coverage'),
      const SizedBox(height: 8),
      if (controlStatus.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No controls reported', style: TextStyle(color: Colors.grey)))
      else ...controlStatus.map((c0) {
        final m = c0 as Map<String,dynamic>;
        return _tile(icon: Icons.security, title: str(m['control']), subtitle: str(m['status']), trailing: '${str(m['coverage'], '0')}%');
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

class _TrendBar extends StatelessWidget {
  final List<int> values;
  final List<String> labels;
  const _TrendBar({required this.values, required this.labels});

  @override
  Widget build(BuildContext context) {
    if (values.isEmpty) return const SizedBox();
    final max = values.fold(0, (a, b) => a > b ? a : b);
    return Row(
      crossAxisAlignment: CrossAxisAlignment.end,
      children: values.asMap().entries.map((e) {
        final v = e.value;
        final pct = max > 0 ? v / max : 0.0;
        final col = pct > .7 ? _kRed : pct > .4 ? _kAmber : _kGreen;
        return Expanded(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 2),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Text('$v', style: const TextStyle(fontSize: 8.5, color: Colors.grey)),
              const SizedBox(height: 2),
              ClipRRect(
                borderRadius: BorderRadius.circular(3),
                child: Container(height: 50 * pct + 4, color: col.withValues(alpha: .7))),
              const SizedBox(height: 4),
              Text(e.key < labels.length ? labels[e.key] : '${e.key + 1}',
                style: const TextStyle(fontSize: 9, color: Colors.grey)),
            ]),
          ),
        );
      }).toList(),
    );
  }
}
