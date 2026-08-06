import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Reports Screen
// ─────────────────────────────────────────────────────────────────────────────

class ReportsScreen extends StatefulWidget {
  final DashboardApi api;
  const ReportsScreen({super.key, required this.api});
  @override State<ReportsScreen> createState() => _ReportsState();
}

class _ReportsState extends State<ReportsScreen> {
  List _reports = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _reports = await widget.api.complianceReports();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  void _showCreate() {
    final titleCtrl = TextEditingController();
    String type = 'summary';
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('Generate Report'),
            const SizedBox(height: 16),
            xField(titleCtrl, 'Report Name'),
            const SizedBox(height: 10),
            xDropdown('Report Type', type, const ['summary', 'executive', 'soc', 'compliance', 'incident'], (v) => ss(() => type = v!)),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.description, size: 16),
              label: const Text('Create'),
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createReport({'name': titleCtrl.text, 'report_type': type});
                if (context.mounted) xSnack(context, ok ? 'Report created' : 'Failed', error: !ok);
                _load();
              },
            )),
          ]),
        ),
      )),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.add),
        label: const Text('Generate'),
      ),
      body: _reports.isEmpty
        ? const XEmptyState('No reports yet', icon: Icons.description_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
              itemCount: _reports.length,
              itemBuilder: (_, i) {
                // rpe_reports: a saved, re-runnable report definition —
                // status is active/archived (not a per-run pending/
                // generating/completed lifecycle); generation history is
                // last_generated_at/generation_count.
                final r   = _reports[i] as Map<String,dynamic>;
                final reportId = str(r['report_id']);
                final genCount = r['generation_count'] ?? 0;
                final col = genCount > 0 ? const Color(0xFF22C55E) : Colors.grey;
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Container(
                      width: 38, height: 38,
                      decoration: BoxDecoration(
                        color: col.withValues(alpha: .1),
                        borderRadius: BorderRadius.circular(9)),
                      child: Icon(Icons.description, size: 18, color: col)),
                    title: Text(str(r['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Text(genCount > 0
                      ? 'Generated $genCount×  ·  last ${timeAgo(r['last_generated_at'])}'
                      : 'Never generated  ·  ${str(r['category'])}',
                      style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    trailing: IconButton(
                      icon: const Icon(Icons.play_arrow, size: 18, color: Color(0xFF22C55E)),
                      tooltip: 'Generate',
                      onPressed: () async {
                        final ok = await widget.api.generateReport(reportId);
                        if (context.mounted) xSnack(context, ok ? 'Generating…' : 'Failed', error: !ok);
                        _load();
                      },
                    ),
                  ),
                );
              },
            ),
          ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Frameworks Screen
// ─────────────────────────────────────────────────────────────────────────────

class FrameworksScreen extends StatefulWidget {
  final DashboardApi api;
  const FrameworksScreen({super.key, required this.api});
  @override State<FrameworksScreen> createState() => _FrameworksState();
}

class _FrameworksState extends State<FrameworksScreen> {
  List _assessments = [];
  bool _loading     = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _assessments = await widget.api.frameworkAssessments();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: RefreshIndicator(
        onRefresh: _load,
        child: _assessments.isEmpty
          ? const XEmptyState('No framework data', icon: Icons.shield_outlined)
          : ListView(
              padding: const EdgeInsets.all(12),
              children: [
                // Compliance ring summary row
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                  children: _assessments.take(4).map((a) {
                    final f     = a as Map<String,dynamic>;
                    final name  = str(f['name']);
                    final score = (f['overall_score'] ?? 0) is num
                      ? (f['overall_score'] as num).toDouble() : 0.0;
                    final col   = _scoreColor(score);
                    return Column(mainAxisSize: MainAxisSize.min, children: [
                      RingGauge(
                        value: score / 100,
                        color: col,
                        size: 68,
                        label: '${score.toInt()}%',
                      ),
                      const SizedBox(height: 4),
                      Text(name, style: const TextStyle(fontSize: 10.5, fontWeight: FontWeight.w700)),
                    ]);
                  }).toList(),
                ),
                const SizedBox(height: 16),
                SectionTitle('Framework Assessments',
                  trailing: TextButton.icon(
                    onPressed: () async {
                      final ok = await widget.api.refreshFrameworks();
                      if (context.mounted) xSnack(context, ok ? 'Refreshed' : 'Failed', error: !ok);
                      _load();
                    },
                    icon: const Icon(Icons.refresh, size: 14),
                    label: const Text('Refresh', style: TextStyle(fontSize: 12)),
                  ),
                ),
                ..._assessments.map((a) {
                  final f     = a as Map<String,dynamic>;
                  final name  = str(f['name']);
                  final score = (f['overall_score'] ?? 0) is num
                    ? (f['overall_score'] as num).toDouble() : 0.0;
                  final passed = (f['passed_controls'] ?? 0) as int? ?? 0;
                  final total  = (f['total_controls']  ?? 0) as int? ?? 0;
                  final col    = _scoreColor(score);
                  return Card(
                    margin: const EdgeInsets.only(bottom: 10),
                    child: Padding(
                      padding: const EdgeInsets.all(14),
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Row(children: [
                          Container(
                            width: 40, height: 40,
                            decoration: BoxDecoration(
                              color: col.withValues(alpha: .1),
                              borderRadius: BorderRadius.circular(10)),
                            child: Icon(Icons.policy, color: col)),
                          const SizedBox(width: 12),
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text(name, style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w800)),
                            if (total > 0)
                              Text('$passed / $total controls passed',
                                style: const TextStyle(fontSize: 12, color: Colors.grey)),
                          ])),
                          Text('${score.toInt()}%',
                            style: TextStyle(fontSize: 22, fontWeight: FontWeight.w900, color: col)),
                        ]),
                        const SizedBox(height: 10),
                        ClipRRect(
                          borderRadius: BorderRadius.circular(4),
                          child: LinearProgressIndicator(
                            value: score / 100, minHeight: 6,
                            backgroundColor: col.withValues(alpha: .12),
                            valueColor: AlwaysStoppedAnimation(col)),
                        ),
                        if (f['last_assessment_at'] != null) ...[
                          const SizedBox(height: 8),
                          Text('Last assessed ${timeAgo(f["last_assessment_at"])}',
                            style: const TextStyle(fontSize: 11, color: Colors.grey)),
                        ],
                      ]),
                    ),
                  );
                }),
              ],
            ),
      ),
    );
  }

  Color _scoreColor(double score) {
    if (score >= 80) return const Color(0xFF22C55E);
    if (score >= 60) return const Color(0xFFF59E0B);
    if (score >= 40) return const Color(0xFFF97316);
    return const Color(0xFFEF4444);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Executive Summary Screen
// ─────────────────────────────────────────────────────────────────────────────

class ExecutiveScreen extends StatefulWidget {
  final DashboardApi api;
  const ExecutiveScreen({super.key, required this.api});
  @override State<ExecutiveScreen> createState() => _ExecutiveState();
}

class _ExecutiveState extends State<ExecutiveScreen> {
  Map<String,dynamic>? _data;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _data = await widget.api.executiveMetrics();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    // GetEXEDashboard wraps everything under "latest" (from exe_snapshots).
    final latest = (_data?['latest'] as Map<String,dynamic>?) ?? {};
    final trend  = (_data?['trend'] as List?) ?? [];
    final score = latest['security_score'] ?? 0;
    final scoreInt = score is num ? score.toInt() : 0;
    final scoreCol = scoreInt >= 75 ? const Color(0xFF22C55E)
                   : scoreInt >= 50 ? const Color(0xFFF59E0B)
                   : const Color(0xFFEF4444);

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          // Big security score gauge
          Center(child: Column(children: [
            RingGauge(
              value: scoreInt / 100, color: scoreCol, size: 120,
              label: '$scoreInt', sublabel: '/ 100'),
            const SizedBox(height: 8),
            Text('Security Score', style: TextStyle(
              fontSize: 14, fontWeight: FontWeight.w700, color: scoreCol)),
            const SizedBox(height: 4),
            Text(
              scoreInt >= 75 ? 'Strong Security Posture'
            : scoreInt >= 50 ? 'Moderate Risk'
            : 'Elevated Risk — Action Required',
              style: const TextStyle(fontSize: 12, color: Colors.grey)),
          ])),
          const SizedBox(height: 20),

          // Key metrics 3-column grid
          GridView.count(
            crossAxisCount: 3,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            crossAxisSpacing: 8, mainAxisSpacing: 8,
            childAspectRatio: 1.1,
            children: [
              KpiCard(label: 'Critical Incidents', value: str(latest['critical_incidents'] ?? 0),
                color: const Color(0xFFEF4444), icon: Icons.warning_amber),
              KpiCard(label: 'Assets', value: str(latest['total_assets'] ?? 0),
                color: const Color(0xFF3B82F6), icon: Icons.computer),
              KpiCard(label: 'Compliance', value: '${(latest['compliance_score'] ?? 0).toString()}%',
                color: const Color(0xFF22C55E), icon: Icons.verified_user),
              KpiCard(label: 'Incidents', value: str(latest['total_incidents'] ?? 0),
                color: const Color(0xFFF97316), icon: Icons.bolt),
              KpiCard(label: 'MTTR (hrs)', value: str(latest['mttr_hours'], '—'),
                color: const Color(0xFF8B5CF6), icon: Icons.speed),
              KpiCard(label: 'Critical Vulns', value: str(latest['critical_vulns'] ?? 0),
                color: const Color(0xFFF97316), icon: Icons.bug_report),
            ],
          ),
          const SizedBox(height: 16),

          // Trend data
          if (trend.isNotEmpty) ...[
            SectionTitle('Incident Trend'),
            _TrendBar(values: trend.map((t) => ((t as Map)['total_incidents'] as num?)?.toInt() ?? 0).toList()),
          ],

          const SizedBox(height: 8),
        ],
      ),
    );
  }

}

class _TrendBar extends StatelessWidget {
  final List<int> values;
  const _TrendBar({required this.values});

  @override
  Widget build(BuildContext context) {
    if (values.isEmpty) return const SizedBox();
    final max = values.fold(0, (a, b) => a > b ? a : b);
    final labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    return Row(
      crossAxisAlignment: CrossAxisAlignment.end,
      children: values.asMap().entries.map((e) {
        final v = e.value;
        final pct = max > 0 ? v / max : 0.0;
        final col = pct > .7 ? const Color(0xFFEF4444)
                  : pct > .4 ? const Color(0xFFF59E0B)
                  :             const Color(0xFF22C55E);
        return Expanded(
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 3),
            child: Column(mainAxisSize: MainAxisSize.min, children: [
              Text('$v', style: const TextStyle(fontSize: 9.5, color: Colors.grey)),
              const SizedBox(height: 2),
              ClipRRect(
                borderRadius: BorderRadius.circular(3),
                child: Container(
                  height: 60 * pct + 4,
                  color: col.withValues(alpha: .7))),
              const SizedBox(height: 4),
              Text(
                e.key < labels.length ? labels[e.key] : '${e.key + 1}',
                style: const TextStyle(fontSize: 9, color: Colors.grey)),
            ]),
          ),
        );
      }).toList(),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// SOC Metrics Screen
// ─────────────────────────────────────────────────────────────────────────────

class SOCMetricsScreen extends StatefulWidget {
  final DashboardApi api;
  const SOCMetricsScreen({super.key, required this.api});
  @override State<SOCMetricsScreen> createState() => _SOCMetricsState();
}

class _SOCMetricsState extends State<SOCMetricsScreen> {
  Map<String,dynamic>? _data;
  Map<String,dynamic>? _alertMetrics;
  List _analysts = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.socMetrics(), widget.api.socAlertMetrics(), widget.api.socAnalysts()]);
    if (!mounted) return;
    setState(() { _data = res[0] as Map<String,dynamic>?; _alertMetrics = res[1] as Map<String,dynamic>?; _analysts = res[2] as List; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    // sme_dashboard's "latest" (unwrapped in DashboardApi.socMetrics) has
    // mttd_mins/mttr_mins/automation_coverage; false_positive_rate lives on
    // the separate /api/sme/alerts response, fetched alongside it above.
    final d = _data ?? {};
    final alertM = _alertMetrics ?? {};
    final cs = Theme.of(context).colorScheme;
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          // SOC efficiency gauges
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceEvenly,
            children: [
              _SocGauge('MTTD', _fmt(d['mttd_mins']), 'min'),
              _SocGauge('MTTR', _fmt(d['mttr_mins']), 'min'),
              _SocGauge('FP Rate', _fmt(alertM['false_positive_rate']), '%'),
              _SocGauge('Automation', _fmt(d['automation_coverage']), '%'),
            ],
          ),
          const SizedBox(height: 20),

          GridView.count(
            crossAxisCount: 2,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            crossAxisSpacing: 8, mainAxisSpacing: 8,
            childAspectRatio: 1.6,
            children: [
              KpiCard(label: 'Active Alerts',    value: str(d['active_alerts'], '—'),
                color: const Color(0xFFF97316), icon: Icons.notifications),
              KpiCard(label: 'Alert Queue',       value: str(d['alert_queue'], '—'),
                color: const Color(0xFF22C55E), icon: Icons.check_circle),
              KpiCard(label: 'Open Cases',       value: str(d['open_cases'], '—'),
                color: const Color(0xFF3B82F6), icon: Icons.folder_open),
              KpiCard(label: 'Playbooks Run',    value: str(d['playbook_executions'], '—'),
                color: const Color(0xFF8B5CF6), icon: Icons.auto_awesome),
              KpiCard(label: 'Analysts Active',  value: str(d['analysts_online'], '—'),
                color: const Color(0xFF6366F1), icon: Icons.people),
              KpiCard(label: 'Escalated',        value: str(alertM['escalated'], '—'),
                color: const Color(0xFFEF4444), icon: Icons.escalator_warning),
            ],
          ),
          const SizedBox(height: 16),

          // Analyst performance — sme_analyst_perf, 30-day aggregate.
          if (_analysts.isNotEmpty) ...[
            SectionTitle('Analyst Performance (30d)'),
            ..._analysts.map((a) {
              final analyst = a as Map<String,dynamic>;
              final prod = ((analyst['productivity_score'] as num?) ?? 0).round();
              final incidents = analyst['incidents_resolved'] ?? 0;
              final cases = analyst['cases_closed'] ?? 0;
              return Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(10),
                  color: cs.surfaceContainerLow),
                child: Row(children: [
                  CircleAvatar(radius: 16,
                    child: Text((str(analyst['name'], 'A')[0]).toUpperCase())),
                  const SizedBox(width: 12),
                  Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(str(analyst['name']),
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 4),
                    HealthBar(prod.clamp(0, 100)),
                  ])),
                  const SizedBox(width: 10),
                  Text('$incidents inc / $cases cases',
                    style: const TextStyle(fontSize: 11, color: Colors.grey)),
                ]),
              );
            }),
          ],
        ],
      ),
    );
  }

  String _fmt(dynamic v) {
    if (v == null) return '—';
    if (v is double) return v.toStringAsFixed(1);
    return str(v);
  }
}

class _SocGauge extends StatelessWidget {
  final String label, value, unit;
  const _SocGauge(this.label, this.value, this.unit);

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      width: 72,
      padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 6),
      decoration: BoxDecoration(
        color: cs.surfaceContainerLow,
        borderRadius: BorderRadius.circular(12)),
      child: Column(children: [
        Text('$value$unit', style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w900),
          overflow: TextOverflow.ellipsis),
        const SizedBox(height: 4),
        Text(label, style: const TextStyle(fontSize: 10, color: Colors.grey),
          textAlign: TextAlign.center),
      ]),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Risk Posture Screen
// ─────────────────────────────────────────────────────────────────────────────

class RiskPostureScreen extends StatefulWidget {
  final DashboardApi api;
  const RiskPostureScreen({super.key, required this.api});
  @override State<RiskPostureScreen> createState() => _RiskPostureState();
}

class _RiskPostureState extends State<RiskPostureScreen> {
  Map<String,dynamic>? _data;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _data = await widget.api.riskPosture();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final d   = _data ?? {};
    // RiskPostureSnapshot has no `categories`/`top_risks` fields — the web
    // page derives 4 category cards client-side from these real sub-scores;
    // mobile shows the sub-scores directly rather than duplicating that
    // client-side scoring formula.
    // Each sub-score has its own max (services.EnrichRiskPostureLiveData:
    // vuln<=30, ueba<=20, alert<=30, ioc<=20 — they sum to the 0-100 overall
    // score) so severity/gauge % must be computed per-category, not against
    // a flat 0-100 scale.
    final categories = [
      {'name': 'Vulnerability', 'score': d['vuln_score'],  'max': 30, 'description': 'Missing patches + critical assets'},
      {'name': 'Identity',      'score': d['ueba_score'],  'max': 20, 'description': 'UEBA anomalies + high-risk identities'},
      {'name': 'Alerting',      'score': d['alert_score'], 'max': 30, 'description': 'Open/snoozed alert backlog'},
      {'name': 'IOC Exposure',  'score': d['ioc_score'],   'max': 20, 'description': 'Matched threat indicators'},
    ];
    final misconfigs = (d['misconfigurations'] as List?) ?? [];
    final identities  = (d['high_risk_identities'] as List?) ?? [];
    final missingPatches = d['missing_patches'] as Map<String,dynamic>?;
    final topRisks = <Map<String,dynamic>>[
      if ((missingPatches?['critical'] ?? 0) is num && (missingPatches?['critical'] ?? 0) > 0)
        {'name': '${missingPatches!['critical']} critical patches missing', 'description': '${missingPatches['overdue'] ?? 0} overdue', 'severity': 'critical'},
      for (final m in misconfigs)
        if (str((m as Map)['severity']) == 'critical' || str(m['severity']) == 'high')
          {'name': str(m['title']), 'description': str(m['asset']), 'severity': str(m['severity'])},
      for (final i in identities)
        if (str((i as Map)['severity']) == 'critical' || str(i['severity']) == 'high')
          {'name': str(i['identity']), 'description': str(i['description']), 'severity': str(i['severity'])},
    ]..sort((a, b) => a['severity'] == 'critical' ? -1 : (b['severity'] == 'critical' ? 1 : 0));

    final overall = (d['score'] ?? 0) is num
      ? (d['score'] ?? 0).toDouble() : 0.0;
    // Higher score = worse (services.EnrichRiskPostureLiveData sums 4
    // penalty sub-scores). The previous thresholds had this inverted —
    // a 90/100 (critical) risk posture rendered green.
    final col = overall >= 70 ? const Color(0xFFEF4444)
              : overall >= 45 ? const Color(0xFFF97316)
              : overall >= 25 ? const Color(0xFFF59E0B)
              : const Color(0xFF22C55E);

    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          // Overall ring
          Center(child: Column(children: [
            RingGauge(value: overall / 100, color: col, size: 100,
              label: '${overall.toInt()}', sublabel: 'Score'),
            const SizedBox(height: 8),
            Text('Overall Risk Posture',
              style: TextStyle(fontSize: 13, fontWeight: FontWeight.w700, color: col)),
          ])),
          const SizedBox(height: 20),

          Row(children: [
            Expanded(child: FilledButton.icon(
              onPressed: () async {
                final ok = await widget.api.refreshRiskPosture();
                if (context.mounted) xSnack(context, ok ? 'Risk posture refreshed' : 'Failed', error: !ok);
                _load();
              },
              icon: const Icon(Icons.refresh, size: 14),
              label: const Text('Refresh Score'),
            )),
          ]),
          const SizedBox(height: 16),

          // Category breakdown
          SectionTitle('Risk Categories'),
          if (categories.isEmpty)
            const Padding(
              padding: EdgeInsets.only(top: 8),
              child: Text('No category data available.', style: TextStyle(color: Colors.grey)),
            )
          else
            ...categories.map((cat) {
              final c     = cat;
              final name  = str(c['name'] ?? c['category']);
              final max   = (c['max'] as num?)?.toDouble() ?? 100.0;
              final score = (c['score'] ?? 0) is num ? (c['score'] as num).toDouble() : 0.0;
              final pct   = max > 0 ? (score / max).clamp(0.0, 1.0) : 0.0;
              final catCol = pct >= .7 ? const Color(0xFFEF4444)
                           : pct >= .4 ? const Color(0xFFF97316)
                           : const Color(0xFF22C55E);
              return Container(
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(12),
                  color: catCol.withValues(alpha: .05),
                  border: Border.all(color: catCol.withValues(alpha: .2))),
                child: Row(children: [
                  RingGauge(value: pct, color: catCol, size: 52,
                    label: '${score.toInt()}'),
                  const SizedBox(width: 14),
                  Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(name, style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700)),
                    if (c['description'] != null)
                      Text(str(c['description']),
                        style: const TextStyle(fontSize: 12, color: Colors.grey),
                        maxLines: 2, overflow: TextOverflow.ellipsis),
                    const SizedBox(height: 6),
                    Row(children: [
                      if (c['findings'] != null)
                        _RiskPill('${c["findings"]} findings', const Color(0xFFF97316)),
                      if (c['controls'] != null)
                        Padding(
                          padding: const EdgeInsets.only(left: 6),
                          child: _RiskPill('${c["controls"]} controls', const Color(0xFF3B82F6))),
                    ]),
                  ])),
                ]),
              );
            }),

          // Top risks — derived from real misconfigurations/high_risk_identities/
          // missing_patches (RiskPostureSnapshot has no `top_risks` field).
          if (topRisks.isNotEmpty) ...[
            const SizedBox(height: 8),
            SectionTitle('Top Risks'),
            ...topRisks.take(5).map((r) {
              final risk    = r;
              final riskcol = sevColor(str(risk['severity']));
              return Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: riskcol.withValues(alpha: .25)),
                  color: riskcol.withValues(alpha: .04)),
                child: Row(children: [
                  Container(width: 4, height: 36, color: riskcol,
                    margin: const EdgeInsets.only(right: 10)),
                  Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(str(risk['name'] ?? risk['title']),
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
                    Text(str(risk['description'] ?? ''),
                      style: const TextStyle(fontSize: 11.5, color: Colors.grey),
                      maxLines: 1, overflow: TextOverflow.ellipsis),
                  ])),
                  SevChip(str(risk['severity'] ?? risk['risk_level'])),
                ]),
              );
            }),
          ],
        ],
      ),
    );
  }
}

class _RiskPill extends StatelessWidget {
  final String label; final Color color;
  const _RiskPill(this.label, this.color);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
    decoration: BoxDecoration(
      color: color.withValues(alpha: .1),
      borderRadius: BorderRadius.circular(6)),
    child: Text(label, style: TextStyle(fontSize: 10, color: color, fontWeight: FontWeight.w700)),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Vulnerability Priority Queue Screen
// ─────────────────────────────────────────────────────────────────────────────

class VulnQueueScreen extends StatefulWidget {
  final DashboardApi api;
  const VulnQueueScreen({super.key, required this.api});
  @override State<VulnQueueScreen> createState() => _VulnQueueState();
}

class _VulnQueueState extends State<VulnQueueScreen> {
  List _vulns   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _vulns = await widget.api.vulnQueue();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: Column(children: [
        if (_vulns.isNotEmpty)
          Padding(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
            child: KpiCard(label: 'Queue Items', value: '${_vulns.length}',
              color: const Color(0xFFEF4444), icon: Icons.bug_report),
          ),
        Expanded(child: _vulns.isEmpty
          ? const XEmptyState('No vulnerabilities in queue', icon: Icons.verified_user)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
                itemCount: _vulns.length,
                itemBuilder: (_, i) {
                  // vq_items — priority/risk_score/status, not
                  // severity/cvss_score (that's vm_findings, a different
                  // table shown on the Vulnerabilities page).
                  final v   = _vulns[i] as Map<String,dynamic>;
                  final id  = v['id'] as int? ?? 0;
                  final pri = str(v['priority']);
                  final col = sevColor(pri);
                  final status = str(v['status'], 'new');
                  final open = !['closed','verified'].contains(status);
                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: col.withValues(alpha: .25)),
                      color: col.withValues(alpha: .04)),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Row(children: [
                        Expanded(child: Text(str(v['cve_id'], 'CVE-Unknown'),
                          style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w800,
                            fontFamily: 'monospace'))),
                        SevChip(pri),
                        const SizedBox(width: 6),
                        StatusChip(status),
                      ]),
                      const SizedBox(height: 4),
                      Text('${str(v['asset_name'], '')}  ·  risk ${str(v['risk_score'], '—')}',
                        style: const TextStyle(fontSize: 12.5, color: Colors.grey),
                        maxLines: 2, overflow: TextOverflow.ellipsis),
                      const SizedBox(height: 8),
                      Row(children: [
                        Text(str(v['assigned_team'], 'Unassigned'),
                          style: const TextStyle(fontSize: 11, color: Colors.grey)),
                        const Spacer(),
                        if (open) ...[
                          TextButton(
                            style: TextButton.styleFrom(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                              tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                            onPressed: () async {
                              final ok = await widget.api.vqAction(id, 'complete');
                              if (context.mounted) xSnack(context, ok ? 'Marked complete' : 'Failed', error: !ok);
                              _load();
                            },
                            child: const Text('Complete', style: TextStyle(fontSize: 12)),
                          ),
                          const SizedBox(width: 6),
                          TextButton(
                            style: TextButton.styleFrom(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                              tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                              foregroundColor: Colors.grey),
                            onPressed: () async {
                              final ok = await widget.api.vqAction(id, 'close');
                              if (context.mounted) xSnack(context, ok ? 'Closed' : 'Failed', error: !ok);
                              _load();
                            },
                            child: const Text('Close', style: TextStyle(fontSize: 12)),
                          ),
                        ],
                      ]),
                    ]),
                  );
                },
              ),
            )),
      ]),
    );
  }
}
