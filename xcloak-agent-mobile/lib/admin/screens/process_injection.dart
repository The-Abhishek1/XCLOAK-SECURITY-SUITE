import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Process Injection — real memory-forensics dashboard backed by /api/pi/*
// (api/process_injection_enterprise.go). Nav id 14 previously showed nothing:
// the shared ItdrScreen filtered /api/itdr/findings?type=process_inject, a
// value that column never actually holds (only brute_force/credential_theft/
// mfa_gap do) — always zero rows. This wires the real, dedicated backend.
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

String _fmtBytes(dynamic v) {
  final n = (v is num) ? v.toDouble() : double.tryParse('$v') ?? 0;
  if (n >= 1073741824) return '${(n / 1073741824).toStringAsFixed(1)} GB';
  if (n >= 1048576) return '${(n / 1048576).toStringAsFixed(1)} MB';
  if (n >= 1024) return '${(n / 1024).toStringAsFixed(1)} KB';
  return '${n.toInt()} B';
}

class ProcessInjectionScreen extends StatefulWidget {
  final DashboardApi api;
  const ProcessInjectionScreen({super.key, required this.api});
  @override State<ProcessInjectionScreen> createState() => _ProcessInjectionState();
}

class _ProcessInjectionState extends State<ProcessInjectionScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 11, vsync: this);

  Map<String,dynamic>? _dashboard, _injections, _memory, _modules, _handles,
      _apiCalls, _behavioral, _threatIntel, _mitre, _analytics;
  List _processes = [], _tree = [], _timeline = [];
  bool _loading = true;
  bool _suspiciousOnly = false;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.piDashboard(),
      widget.api.piProcesses(suspiciousOnly: _suspiciousOnly),
      widget.api.piProcessTree(),
      widget.api.piInjections(),
      widget.api.piMemory(),
      widget.api.piModules(),
      widget.api.piHandles(),
      widget.api.piApiCalls(),
      widget.api.piBehavioral(),
      widget.api.piThreatIntel(),
      widget.api.piTimeline(),
      widget.api.piMitreMap(),
      widget.api.piAnalytics(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard   = r[0]  as Map<String,dynamic>?;
      _processes   = r[1]  as List;
      _tree        = r[2]  as List;
      _injections  = r[3]  as Map<String,dynamic>?;
      _memory      = r[4]  as Map<String,dynamic>?;
      _modules     = r[5]  as Map<String,dynamic>?;
      _handles     = r[6]  as Map<String,dynamic>?;
      _apiCalls    = r[7]  as Map<String,dynamic>?;
      _behavioral  = r[8]  as Map<String,dynamic>?;
      _threatIntel = r[9]  as Map<String,dynamic>?;
      _timeline    = r[10] as List;
      _mitre       = r[11] as Map<String,dynamic>?;
      _analytics   = r[12] as Map<String,dynamic>?;
      _loading     = false;
    });
  }

  Future<void> _toggleSuspicious(bool v) async {
    setState(() => _suspiciousOnly = v);
    final procs = await widget.api.piProcesses(suspiciousOnly: v);
    if (!mounted) return;
    setState(() => _processes = procs);
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Processes'), Tab(text: 'Process Tree'),
        Tab(text: 'Injections'), Tab(text: 'Memory'), Tab(text: 'Modules/Handles'),
        Tab(text: 'API Calls'), Tab(text: 'Threat Intel'), Tab(text: 'Timeline'),
        Tab(text: 'MITRE Map'), Tab(text: 'Analytics'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _processesTab(), _processTreeTab(), _injectionsTab(),
        _memoryTab(), _modulesHandlesTab(), _apiCallsTab(), _threatIntelTab(),
        _timelineTab(), _mitreTab(), _analyticsTab(),
      ])),
    ]);
  }

  Widget _overviewTab() {
    final d = _dashboard ?? {};
    final types = ((d['injection_types'] as List?) ?? []).cast<dynamic>();
    final recentInjections = ((_injections?['injections'] as List?) ?? []).take(5).toList();
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Injection Alerts', value: str(d['injection_alerts'], '0'), color: _kRed, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Active Injections', value: str(d['active_injections'], '0'), color: _kOrange, icon: Icons.memory)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Suspicious Procs', value: str(d['suspicious_processes'], '0'), color: _kAmber, icon: Icons.dangerous_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Protected Procs', value: str(d['protected_processes'], '0'), color: _kGreen, icon: Icons.verified_user)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Memory Mods', value: str(d['memory_modifications'], '0'), color: _kPurple, icon: Icons.sd_storage)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'High-Risk Hosts', value: str(d['high_risk_hosts'], '0'), color: _kRed, icon: Icons.dns)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Detection Coverage', value: '${str(d['detection_coverage'], '0')}%', color: _kBlue, icon: Icons.gpp_good)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Techniques Monitored', value: '${types.length}', color: _kBlue, icon: Icons.rule)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Injection Techniques Monitored'),
      const SizedBox(height: 8),
      Wrap(spacing: 6, runSpacing: 6, children: types.map((t) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
        decoration: BoxDecoration(color: _kBlue.withValues(alpha: .08), borderRadius: BorderRadius.circular(8)),
        child: Text('$t', style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600)),
      )).toList()),
      if (recentInjections.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Recent Injections'),
        const SizedBox(height: 8),
        ...recentInjections.map((i0) {
          final m = i0 as Map<String,dynamic>;
          return _tile(
            icon: Icons.bolt, iconColor: sevColor(str(m['severity'])),
            title: '${str(m['src_name'])} → ${str(m['dst_name'])}',
            subtitle: '${str(m['technique']).replaceAll('_', ' ')} · ${str(m['hostname'])}',
            trailing: timeAgo(m['created_at']),
          );
        }),
      ],
    ]));
  }

  Widget _processesTab() {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
        child: FilterRow(
          chips: [('All', 'all', null), ('Suspicious Only', 'susp', null)],
          selected: _suspiciousOnly ? 'susp' : 'all',
          onSelect: (v) => _toggleSuspicious(v == 'susp'),
        ),
      ),
      Expanded(child: _processes.isEmpty
        ? const XEmptyState('No processes observed', icon: Icons.memory_outlined)
        : RefreshIndicator(onRefresh: _load, child: ListView.builder(
            padding: const EdgeInsets.all(12), itemCount: _processes.length,
            itemBuilder: (_, i) {
              final p = _processes[i] as Map<String,dynamic>;
              final risk = (p['risk_score'] as num?)?.toInt() ?? 0;
              final suspicious = risk > 60;
              return Container(
                margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: suspicious ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
                  color: suspicious ? _kRed.withValues(alpha: .04) : null),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Expanded(child: Text('${str(p['name'])} (pid ${str(p['pid'],'0')})',
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
                    Text('$risk', style: TextStyle(fontWeight: FontWeight.w800,
                      color: suspicious ? _kRed : _kAmber)),
                  ]),
                  const SizedBox(height: 4),
                  Text('${str(p['hostname'])} · ${str(p['username'])} · ppid ${str(p['ppid'],'0')}',
                    style: const TextStyle(fontSize: 11, color: Colors.grey)),
                  if (str(p['cmdline']).isNotEmpty) ...[
                    const SizedBox(height: 4),
                    Text(str(p['cmdline']), style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                      maxLines: 2, overflow: TextOverflow.ellipsis),
                  ],
                  const SizedBox(height: 6),
                  Row(children: [
                    if (str(p['signature']).isNotEmpty) _Pill(label: 'SIGNED', color: _kGreen),
                    if (str(p['integrity_level']).isNotEmpty) ...[
                      const SizedBox(width: 4),
                      _Pill(label: str(p['integrity_level']).toUpperCase(), color: _kBlue),
                    ],
                    const Spacer(),
                    Text(str(p['sha256']).isEmpty ? '' : '${str(p['sha256']).substring(0, str(p['sha256']).length > 12 ? 12 : str(p['sha256']).length)}…',
                      style: const TextStyle(fontSize: 10, color: Colors.grey, fontFamily: 'monospace')),
                  ]),
                ]),
              );
            },
          )),
      ),
    ]);
  }

  Widget _processTreeTab() {
    if (_tree.isEmpty) return const XEmptyState('No process tree data', icon: Icons.account_tree_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _tree.length,
      itemBuilder: (_, i) {
        final n = _tree[i] as Map<String,dynamic>;
        final risk = (n['risk_score'] as num?)?.toInt() ?? 0;
        return _tile(
          icon: Icons.account_tree_outlined, iconColor: risk > 60 ? _kRed : Colors.grey,
          title: '${str(n['name'])} (pid ${str(n['pid'],'0')})',
          subtitle: 'parent pid ${str(n['ppid'],'0')} · ${str(n['username'])}',
          trailing: 'risk $risk',
        );
      },
    ));
  }

  Widget _injectionsTab() {
    final list = (_injections?['injections'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Total', value: str(_injections?['total'], '0'), color: _kBlue, icon: Icons.list_alt)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Critical', value: str(_injections?['critical'], '0'), color: _kRed, icon: Icons.priority_high)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Injection Events'),
      const SizedBox(height: 8),
      if (list.isEmpty) const XEmptyState('No injection events detected', icon: Icons.shield_outlined)
      else ...list.map((i0) {
        final m = i0 as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text('${str(m['src_name'])} (${str(m['src_pid'],'0')}) → ${str(m['dst_name'])} (${str(m['dst_pid'],'0')})',
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['technique']).replaceAll('_', ' ')} · ${str(m['api_call'])} · ${str(m['hostname'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['mitre_technique']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('MITRE ${str(m['mitre_technique'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
            ],
            const SizedBox(height: 4),
            Text('${str(m['status']).toUpperCase()} · ${timeAgo(m['created_at'])}',
              style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            const SizedBox(height: 8),
            Row(children: [
              TextButton(onPressed: () => _respond('kill_process', m), child: const Text('Kill Process', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('collect_process', m), child: const Text('Collect', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('isolate_endpoint', m), child: const Text('Isolate Host', style: TextStyle(fontSize: 11))),
            ]),
          ]),
        );
      }),
    ]));
  }

  Future<void> _respond(String action, Map<String,dynamic> m) async {
    final res = await widget.api.piRespond({
      'action': action,
      // '' fallback, not str()'s default '—' — the backend treats an empty
      // hostname/target as "not provided" and returns a real validation
      // error; sending the placeholder glyph instead masks that check and
      // surfaces a confusing "no agent found with hostname '—'" error.
      'target': str(m['dst_name'], ''),
      'pid': m['dst_pid'] as int? ?? 0,
      'hostname': str(m['hostname'], ''),
      'reason': 'Process injection: ${str(m['technique'])}',
    });
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  Widget _memoryTab() {
    final regions = (_memory?['regions'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'RWX Pages', value: str(_memory?['rwx_pages'], '0'), color: _kRed, icon: Icons.security)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Shellcode', value: str(_memory?['shellcode'], '0'), color: _kRed, icon: Icons.dangerous)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Unbacked Regions', value: str(_memory?['unbacked'], '0'), color: _kAmber, icon: Icons.help_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Regions Scanned', value: '${regions.length}', color: _kBlue, icon: Icons.storage)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Memory Regions'),
      const SizedBox(height: 8),
      if (regions.isEmpty) const XEmptyState('No memory regions scanned', icon: Icons.memory_outlined)
      else ...regions.map((r0) {
        final m = r0 as Map<String,dynamic>;
        final suspicious = m['is_suspicious'] == true;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: suspicious ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: suspicious ? _kRed.withValues(alpha: .04) : null),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text('${str(m['process_name'])} (pid ${str(m['pid'],'0')})',
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text(_fmtBytes(m['size_bytes']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['hostname'])} · ${str(m['region_type'])} · ${str(m['base_addr'])} · ${str(m['protection'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 6),
            Wrap(spacing: 4, runSpacing: 4, children: [
              if (m['is_executable'] == true) _Pill(label: 'EXEC', color: _kOrange),
              if (m['contains_shellcode'] == true) _Pill(label: 'SHELLCODE', color: _kRed),
              if (m['is_backed'] != true) _Pill(label: 'UNBACKED', color: _kAmber),
              _Pill(label: 'entropy ${str(m['entropy'],'0')}', color: _kBlue),
            ]),
          ]),
        );
      }),
    ]));
  }

  Widget _modulesHandlesTab() {
    final modules = (_modules?['modules'] as List?) ?? [];
    final handles = (_handles?['handles'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Loaded Modules'),
      const SizedBox(height: 8),
      if (modules.isEmpty)
        const XEmptyState('No agent capability collects per-process\nloaded-module inventories yet', icon: Icons.extension_off_outlined)
      else ...modules.map((m0) {
        final m = m0 as Map<String,dynamic>;
        return _tile(icon: Icons.extension_outlined, title: str(m['name']), subtitle: str(m['path']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Open Handles'),
      const SizedBox(height: 8),
      if (handles.isEmpty)
        const XEmptyState('No agent capability collects per-process\nhandle tables yet', icon: Icons.key_off_outlined)
      else ...handles.map((h0) {
        final m = h0 as Map<String,dynamic>;
        return _tile(icon: Icons.vpn_key_outlined, title: str(m['type']), subtitle: str(m['name']));
      }),
    ]));
  }

  Widget _apiCallsTab() {
    final calls = (_apiCalls?['api_calls'] as List?) ?? [];
    final monitored = ((_apiCalls?['monitored_apis'] as List?) ?? []).cast<dynamic>();
    final detections = (_behavioral?['detections'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Monitored APIs'),
      const SizedBox(height: 8),
      Wrap(spacing: 6, runSpacing: 6, children: monitored.map((a) => Container(
        padding: const EdgeInsets.symmetric(horizontal: 9, vertical: 5),
        decoration: BoxDecoration(color: _kPurple.withValues(alpha: .08), borderRadius: BorderRadius.circular(8)),
        child: Text('$a', style: const TextStyle(fontSize: 11, fontWeight: FontWeight.w600, color: _kPurple)),
      )).toList()),
      const SizedBox(height: 16),
      SectionTitle('Observed Calls'),
      const SizedBox(height: 8),
      if (calls.isEmpty) const XEmptyState('No suspicious API calls observed', icon: Icons.api_outlined)
      else ...calls.map((c0) {
        final m = c0 as Map<String,dynamic>;
        final susp = m['is_suspicious'] == true;
        return _tile(
          icon: Icons.api, iconColor: susp ? _kRed : Colors.grey,
          title: str(m['api_name']),
          subtitle: '${str(m['process_name'])} (${str(m['pid'],'0')}) → pid ${str(m['target_pid'],'0')} · ${str(m['hostname'])}',
          trailing: susp ? 'SUSPICIOUS' : null,
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Behavioral Detections'),
      const SizedBox(height: 8),
      if (detections.isEmpty) const XEmptyState('No behavioral detections', icon: Icons.psychology_outlined)
      else ...detections.map((d0) {
        final m = d0 as Map<String,dynamic>;
        return _tile(
          icon: Icons.psychology_alt_outlined, iconColor: sevColor(str(m['severity'])),
          title: str(m['rule']),
          subtitle: '${str(m['cmdline'])} · ${str(m['hostname'])}',
          trailing: str(m['mitre']),
        );
      }),
    ]));
  }

  Widget _threatIntelTab() {
    final matches = (_threatIntel?['malware_matches'] as List?) ?? [];
    if (matches.isEmpty) return const XEmptyState('No IOC matches against observed process hashes', icon: Icons.gpp_maybe_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: matches.length,
      itemBuilder: (_, i) {
        final m = matches[i] as Map<String,dynamic>;
        final sev = str(m['severity']);
        return _tile(
          icon: Icons.bug_report, iconColor: sevColor(sev),
          title: str(m['process']),
          subtitle: str(m['sha256']),
          trailing: '${str(m['hits'])} hits',
        );
      },
    ));
  }

  Widget _timelineTab() {
    if (_timeline.isEmpty) return const XEmptyState('No injection alerts recorded', icon: Icons.history_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _timeline.length,
      itemBuilder: (_, i) {
        final m = _timeline[i] as Map<String,dynamic>;
        return TimelineEntry(
          icon: Icons.bolt,
          color: sevColor(str(m['severity'])),
          title: str(m['title']),
          subtitle: '${str(m['description'])} · ${str(m['hostname'])}',
          time: timeAgo(m['created_at']),
          isLast: i == _timeline.length - 1,
        );
      },
    ));
  }

  Widget _mitreTab() {
    final parent = (_mitre?['parent'] as Map?)?.cast<String,dynamic>() ?? {};
    final subs = (_mitre?['sub_techniques'] as List?) ?? [];
    final related = (_mitre?['related'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(borderRadius: BorderRadius.circular(12), color: _kPurple.withValues(alpha: .08)),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('${str(parent['technique_id'])} · ${str(parent['name'])}',
            style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w800, color: _kPurple)),
          const SizedBox(height: 4),
          Text(str(parent['tactic']), style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
        ]),
      ),
      const SizedBox(height: 16),
      SectionTitle('Sub-Techniques'),
      const SizedBox(height: 8),
      ...subs.map((s0) {
        final m = s0 as Map<String,dynamic>;
        final detected = m['detected'] == true;
        return _tile(
          icon: detected ? Icons.check_circle : Icons.radio_button_unchecked,
          iconColor: detected ? _kGreen : Colors.grey,
          title: '${str(m['id'])} · ${str(m['name'])}',
          trailing: detected ? '${str(m['count'])} seen' : 'not observed',
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Related Techniques'),
      const SizedBox(height: 8),
      ...related.map((r0) {
        final m = r0 as Map<String,dynamic>;
        final detected = m['detected'] == true;
        return _tile(
          icon: detected ? Icons.link : Icons.link_off,
          iconColor: detected ? _kAmber : Colors.grey,
          title: '${str(m['id'])} · ${str(m['name'])}',
          subtitle: str(m['tactic']),
          trailing: detected ? 'OBSERVED' : null,
        );
      }),
    ]));
  }

  Widget _analyticsTab() {
    final trend = (_analytics?['injection_trend'] as List?) ?? [];
    final topTechniques = (_analytics?['top_techniques'] as List?) ?? [];
    final targetedProcs = (_analytics?['most_targeted_processes'] as List?) ?? [];
    final usedApis = (_analytics?['most_used_apis'] as List?) ?? [];
    final riskHosts = (_analytics?['high_risk_hosts'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Injection Trend (14 days)'),
      const SizedBox(height: 8),
      if (trend.isNotEmpty)
        SizedBox(height: 40, child: Row(crossAxisAlignment: CrossAxisAlignment.end, children: trend.map((t0) {
          final m = t0 as Map<String,dynamic>;
          final cnt = (m['count'] as num?)?.toDouble() ?? 0;
          final maxCnt = trend.map((e) => ((e as Map)['count'] as num?)?.toDouble() ?? 0).fold(1.0, (a, b) => b > a ? b : a);
          return Expanded(child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 1),
            child: Container(
              height: (cnt / maxCnt * 36).clamp(2.0, 36.0),
              decoration: BoxDecoration(color: _kBlue.withValues(alpha: .6), borderRadius: BorderRadius.circular(2)),
            ),
          ));
        }).toList())),
      const SizedBox(height: 16),
      SectionTitle('Top Techniques'),
      const SizedBox(height: 8),
      if (topTechniques.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No technique data yet', style: TextStyle(color: Colors.grey)))
      else ...topTechniques.map((t0) {
        final m = t0 as Map<String,dynamic>;
        return _tile(icon: Icons.category, iconColor: sevColor(str(m['severity'])),
          title: str(m['technique']).replaceAll('_', ' '), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Most Targeted Processes'),
      const SizedBox(height: 8),
      ...targetedProcs.map((p0) {
        final m = p0 as Map<String,dynamic>;
        return _tile(icon: Icons.adjust, iconColor: sevColor(str(m['risk'])),
          title: str(m['process']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Most Used APIs'),
      const SizedBox(height: 8),
      ...usedApis.map((a0) {
        final m = a0 as Map<String,dynamic>;
        return _tile(icon: Icons.functions, title: str(m['api']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('High-Risk Hosts'),
      const SizedBox(height: 8),
      ...riskHosts.map((h0) {
        final m = h0 as Map<String,dynamic>;
        return _tile(icon: Icons.dns, title: str(m['hostname']),
          subtitle: '${str(m['injection_count'])} injections', trailing: 'risk ${str(m['risk'])}');
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
