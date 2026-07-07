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
            xField(titleCtrl, 'Report Title'),
            const SizedBox(height: 10),
            xDropdown('Report Type', type, const ['summary', 'executive', 'soc', 'compliance', 'incident'], (v) => ss(() => type = v!)),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.description, size: 16),
              label: const Text('Generate'),
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createReport({
                  'title': titleCtrl.text, 'report_type': type,
                  'period_start': DateTime.now().subtract(const Duration(days: 30)).toIso8601String(),
                  'period_end':   DateTime.now().toIso8601String(),
                });
                if (context.mounted) xSnack(context, ok ? 'Report generation started' : 'Failed', error: !ok);
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
                final r   = _reports[i] as Map<String,dynamic>;
                final id  = r['id'] as int? ?? 0;
                final st  = str(r['status']);
                final col = st == 'completed' ? const Color(0xFF22C55E)
                          : st == 'generating' ? const Color(0xFFF59E0B)
                          : Colors.grey;
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Container(
                      width: 38, height: 38,
                      decoration: BoxDecoration(
                        color: col.withOpacity(.1),
                        borderRadius: BorderRadius.circular(9)),
                      child: Icon(Icons.description, size: 18, color: col)),
                    title: Text(str(r['title']), style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Row(children: [
                      StatusChip(st),
                      const SizedBox(width: 6),
                      Text(timeAgo(r['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    ]),
                    trailing: st == 'completed'
                      ? IconButton(
                          icon: const Icon(Icons.download, size: 18),
                          onPressed: () => xSnack(context, 'Download via web console'),
                        )
                      : st == 'pending'
                        ? IconButton(
                            icon: const Icon(Icons.play_arrow, size: 18, color: Color(0xFF22C55E)),
                            onPressed: () async {
                              final ok = await widget.api.generateReport(id);
                              if (context.mounted) xSnack(context, ok ? 'Generating…' : 'Failed', error: !ok);
                              _load();
                            },
                          )
                        : null,
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
                    final name  = str(f['framework'] ?? f['name']);
                    final score = (f['compliance_score'] ?? f['score'] ?? 0) is num
                      ? (f['compliance_score'] ?? f['score'] ?? 0).toDouble() : 0.0;
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
                  final name  = str(f['framework'] ?? f['name']);
                  final score = (f['compliance_score'] ?? f['score'] ?? 0) is num
                    ? (f['compliance_score'] ?? f['score'] ?? 0).toDouble() : 0.0;
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
                              color: col.withOpacity(.1),
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
                            backgroundColor: col.withOpacity(.12),
                            valueColor: AlwaysStoppedAnimation(col)),
                        ),
                        if (f['last_assessed'] != null) ...[
                          const SizedBox(height: 8),
                          Text('Last assessed ${timeAgo(f["last_assessed"])}',
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
    final d   = _data ?? {};
    final score = (d['overall_security_score'] ?? d['risk_score'] ?? d['score'] ?? 0);
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
              KpiCard(label: 'Open Threats', value: str(d['open_threats'] ?? d['open_alerts'] ?? 0),
                color: const Color(0xFFEF4444), icon: Icons.warning_amber),
              KpiCard(label: 'Endpoints', value: str(d['total_endpoints'] ?? d['total_agents'] ?? 0),
                color: const Color(0xFF3B82F6), icon: Icons.computer),
              KpiCard(label: 'Compliance', value: '${(d['compliance_score'] ?? 0).toString()}%',
                color: const Color(0xFF22C55E), icon: Icons.verified_user),
              KpiCard(label: 'Incidents', value: str(d['active_incidents'] ?? 0),
                color: const Color(0xFFF97316), icon: Icons.bolt),
              KpiCard(label: 'MTTR (min)', value: str(d['mttr'] ?? d['mean_time_to_respond'] ?? '—'),
                color: const Color(0xFF8B5CF6), icon: Icons.speed),
              KpiCard(label: 'Data Risk', value: str(d['data_risk_score'] ?? '—'),
                color: const Color(0xFFF97316), icon: Icons.storage),
            ],
          ),
          const SizedBox(height: 16),

          // Highlights
          if (d['highlights'] != null || d['summary'] != null) ...[
            SectionTitle('Executive Highlights'),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: Theme.of(context).colorScheme.surfaceContainerLow,
                borderRadius: BorderRadius.circular(12)),
              child: Text(
                str(d['highlights'] ?? d['summary'] ?? 'No executive summary available.'),
                style: const TextStyle(fontSize: 13.5, height: 1.55)),
            ),
            const SizedBox(height: 16),
          ],

          // Trend data
          if (d['threat_trend'] != null || d['alert_trend'] != null) ...[
            SectionTitle('Threat Trend (last 7 days)'),
            _TrendBar(values: _parseTrend(d['threat_trend'] ?? d['alert_trend'])),
          ],

          const SizedBox(height: 8),
        ],
      ),
    );
  }

  List<int> _parseTrend(dynamic raw) {
    if (raw is List) return raw.map((v) => v is num ? v.toInt() : 0).toList();
    return [];
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
                  color: col.withOpacity(.7))),
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
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _data = await widget.api.socMetrics();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final d = _data ?? {};
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
              _SocGauge('MTTD', _fmt(d['mttd'] ?? d['mean_time_to_detect']), 'min'),
              _SocGauge('MTTR', _fmt(d['mttr'] ?? d['mean_time_to_respond']), 'min'),
              _SocGauge('FP Rate', _fmt(d['false_positive_rate']), '%'),
              _SocGauge('Coverage', _fmt(d['detection_coverage']), '%'),
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
              KpiCard(label: 'Alerts Today',     value: str(d['alerts_today'] ?? d['alert_volume'] ?? '—'),
                color: const Color(0xFFF97316), icon: Icons.notifications),
              KpiCard(label: 'Resolved Today',   value: str(d['resolved_today'] ?? '—'),
                color: const Color(0xFF22C55E), icon: Icons.check_circle),
              KpiCard(label: 'Open Cases',       value: str(d['open_cases'] ?? '—'),
                color: const Color(0xFF3B82F6), icon: Icons.folder_open),
              KpiCard(label: 'Playbooks Run',    value: str(d['playbooks_triggered'] ?? '—'),
                color: const Color(0xFF8B5CF6), icon: Icons.auto_awesome),
              KpiCard(label: 'Analysts Active',  value: str(d['active_analysts'] ?? '—'),
                color: const Color(0xFF6366F1), icon: Icons.people),
              KpiCard(label: 'Escalated',        value: str(d['escalated_today'] ?? '—'),
                color: const Color(0xFFEF4444), icon: Icons.escalator_warning),
            ],
          ),
          const SizedBox(height: 16),

          // Analyst performance
          if (d['analyst_metrics'] is List) ...[
            SectionTitle('Analyst Performance'),
            ...(d['analyst_metrics'] as List).map((a) {
              final analyst = a as Map<String,dynamic>;
              final closed  = (analyst['closed'] ?? 0) as int? ?? 0;
              final total   = (analyst['assigned'] ?? 0) as int? ?? 0;
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
                    HealthBar(total > 0 ? (closed * 100 ~/ total) : 0),
                  ])),
                  const SizedBox(width: 10),
                  Text('$closed / $total',
                    style: const TextStyle(fontSize: 12, color: Colors.grey)),
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
    final categories = (d['categories'] as List?) ??
        (d['risk_categories'] as List?) ?? [];

    final overall = (d['overall_score'] ?? d['score'] ?? 0) is num
      ? (d['overall_score'] ?? d['score'] ?? 0).toDouble() : 0.0;
    final col = overall >= 75 ? const Color(0xFF22C55E)
              : overall >= 50 ? const Color(0xFFF59E0B)
              : const Color(0xFFEF4444);

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
              final c     = cat as Map<String,dynamic>;
              final name  = str(c['name'] ?? c['category']);
              final score = (c['score'] ?? c['risk_score'] ?? 0) is num
                ? (c['score'] ?? c['risk_score'] ?? 0).toDouble() : 0.0;
              final catCol = score >= 75 ? const Color(0xFF22C55E)
                           : score >= 50 ? const Color(0xFFF59E0B)
                           : const Color(0xFFEF4444);
              return Container(
                margin: const EdgeInsets.only(bottom: 10),
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(12),
                  color: catCol.withOpacity(.05),
                  border: Border.all(color: catCol.withOpacity(.2))),
                child: Row(children: [
                  RingGauge(value: score / 100, color: catCol, size: 52,
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

          // Top risks
          if (d['top_risks'] is List) ...[
            const SizedBox(height: 8),
            SectionTitle('Top Risks'),
            ...(d['top_risks'] as List).take(5).map((r) {
              final risk    = r as Map<String,dynamic>;
              final riskcol = sevColor(str(risk['severity'] ?? risk['risk_level']));
              return Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: riskcol.withOpacity(.25)),
                  color: riskcol.withOpacity(.04)),
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
      color: color.withOpacity(.1),
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
            child: Row(children: [
              Expanded(child: KpiCard(label: 'Total Vulns', value: '${_vulns.length}',
                color: const Color(0xFFEF4444), icon: Icons.bug_report)),
              const SizedBox(width: 8),
              TextButton.icon(
                onPressed: () async {
                  final ok = await widget.api.refreshVulnPriorities();
                  if (context.mounted) xSnack(context, ok ? 'Priorities refreshed' : 'Failed', error: !ok);
                  _load();
                },
                icon: const Icon(Icons.refresh, size: 14),
                label: const Text('Refresh', style: TextStyle(fontSize: 12)),
              ),
            ]),
          ),
        Expanded(child: _vulns.isEmpty
          ? const XEmptyState('No vulnerabilities in queue', icon: Icons.verified_user)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
                itemCount: _vulns.length,
                itemBuilder: (_, i) {
                  final v   = _vulns[i] as Map<String,dynamic>;
                  final id  = v['id'] as int? ?? 0;
                  final sev = str(v['severity']);
                  final col = sevColor(sev);
                  final cvss = (v['cvss_score'] ?? v['score'] ?? 0.0);
                  return Container(
                    margin: const EdgeInsets.only(bottom: 8),
                    padding: const EdgeInsets.all(14),
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: col.withOpacity(.25)),
                      color: col.withOpacity(.04)),
                    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Row(children: [
                        Expanded(child: Text(str(v['cve_id'] ?? v['title'] ?? 'CVE-Unknown'),
                          style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w800,
                            fontFamily: 'monospace'))),
                        SevChip(sev),
                        const SizedBox(width: 6),
                        Text('${cvss is num ? cvss.toStringAsFixed(1) : cvss}',
                          style: TextStyle(fontSize: 13, fontWeight: FontWeight.w800, color: col)),
                      ]),
                      const SizedBox(height: 4),
                      Text(str(v['package'] ?? v['affected_component'] ?? v['description'] ?? ''),
                        style: const TextStyle(fontSize: 12.5, color: Colors.grey),
                        maxLines: 2, overflow: TextOverflow.ellipsis),
                      const SizedBox(height: 8),
                      Row(children: [
                        Text('${str(v['affected_count'] ?? 1)} hosts',
                          style: const TextStyle(fontSize: 11, color: Colors.grey)),
                        const Spacer(),
                        TextButton(
                          style: TextButton.styleFrom(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                            tapTargetSize: MaterialTapTargetSize.shrinkWrap),
                          onPressed: () async {
                            final ok = await widget.api.updatePatchStatus(id, 'patched');
                            if (context.mounted) xSnack(context, ok ? 'Marked as patched' : 'Failed', error: !ok);
                            _load();
                          },
                          child: const Text('Mark Patched', style: TextStyle(fontSize: 12)),
                        ),
                        const SizedBox(width: 6),
                        TextButton(
                          style: TextButton.styleFrom(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                            tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                            foregroundColor: Colors.grey),
                          onPressed: () async {
                            final ok = await widget.api.updatePatchStatus(id, 'accepted');
                            if (context.mounted) xSnack(context, ok ? 'Risk accepted' : 'Failed', error: !ok);
                            _load();
                          },
                          child: const Text('Accept Risk', style: TextStyle(fontSize: 12)),
                        ),
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
