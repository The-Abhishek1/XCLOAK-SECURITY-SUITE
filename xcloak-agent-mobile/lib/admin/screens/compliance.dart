import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── Reports ───────────────────────────────────────────────────────────────────

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
    final r = await widget.api.reports();
    if (!mounted) return;
    setState(() { _reports = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _reports.isEmpty ? const XEmptyState('No reports') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _reports.length,
          itemBuilder: (_, i) {
            final r  = _reports[i] as Map<String,dynamic>;
            final id = r['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: Icon(Icons.description, color: statusColor(str(r['status']))),
              title: Text(str(r['name'] ?? r['title'] ?? 'Report $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text('${str(r['report_type'] ?? r['type'] ?? '')}  ·  ${str(r['status'])}  ·  ${timeAgo(r['created_at'])}'),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'generate') { await widget.api.generateReport(id); xSnack(context, 'Report generation started'); _load(); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Report', 'Delete this report?')) { await widget.api.deleteReport(id); _load(); }
                  }
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'generate', child: Text('Regenerate')),
                  PopupMenuItem(value: 'delete',   child: Text('Delete', style: TextStyle(color: Colors.red))),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  void _create() {
    final nameCtrl = TextEditingController();
    String type = 'summary';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Report', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Report Name'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['summary','incident','compliance','executive','threat_intel'], (v) => ss(() => type = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createReport({'name': nameCtrl.text.trim(), 'report_type': type});
              xSnack(context, 'Report queued');
              _load();
            },
            child: const Text('Create & Generate'),
          )),
        ]),
      )),
    );
  }
}

// ── Frameworks ────────────────────────────────────────────────────────────────

class FrameworksScreen extends StatefulWidget {
  final DashboardApi api;
  const FrameworksScreen({super.key, required this.api});
  @override State<FrameworksScreen> createState() => _FrameworksState();
}

class _FrameworksState extends State<FrameworksScreen> {
  List _fw = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.frameworks();
    if (!mounted) return;
    setState(() { _fw = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _fw.isEmpty ? const XEmptyState('No compliance frameworks') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _fw.length,
          itemBuilder: (_, i) {
            final f = _fw[i] as Map<String,dynamic>;
            final pct = (f['compliance_score'] ?? f['score'] ?? 0) as num;
            return Card(child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(child: Text(str(f['name']), style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 15))),
                  Text('${pct.round()}%', style: TextStyle(color: pct >= 80 ? Colors.green : pct >= 60 ? Colors.orange : Colors.red, fontWeight: FontWeight.bold)),
                ]),
                const SizedBox(height: 8),
                LinearProgressIndicator(
                  value: pct / 100,
                  backgroundColor: Colors.grey.shade300,
                  color: pct >= 80 ? Colors.green : pct >= 60 ? Colors.orange : Colors.red,
                  minHeight: 6,
                ),
                const SizedBox(height: 4),
                Text(
                  '${f['passed_controls'] ?? 0} / ${f['total_controls'] ?? '?'} controls passed',
                  style: const TextStyle(fontSize: 11, color: Colors.grey),
                ),
              ]),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async { await widget.api.refreshFrameworks(); xSnack(context, 'Refresh triggered'); },
        icon: const Icon(Icons.refresh),
        label: const Text('Refresh'),
      ),
    );
  }
}

// ── Executive Report ──────────────────────────────────────────────────────────

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
    final r = await widget.api.executiveSummary();
    if (!mounted) return;
    setState(() { _data = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final d = _data ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          const Text('EXECUTIVE SUMMARY', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.5, fontWeight: FontWeight.bold)),
          const SizedBox(height: 10),
          StatRow([
            ('Risk Score',      str(d['risk_score'] ?? 0),            Colors.red),
            ('Compliance',      '${d['compliance_score'] ?? 0}%',     Colors.blue),
          ]),
          StatRow([
            ('Open Incidents',  str(d['open_incidents'] ?? 0),         Colors.orange),
            ('Resolved (30d)',  str(d['resolved_30d'] ?? 0),           Colors.green),
          ]),
          StatRow([
            ('Critical Vulns',  str(d['critical_vulns'] ?? 0),         Colors.red),
            ('High Vulns',      str(d['high_vulns'] ?? 0),             Colors.orange),
          ]),
          const SizedBox(height: 12),
          if (d['trend_alerts'] != null) _trendCard('Alert Trend (7d)', d['trend_alerts'] as List),
          const SizedBox(height: 8),
          if (d['top_threats'] is List) ...[
            const Text('TOP THREATS', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
            const SizedBox(height: 6),
            ...(d['top_threats'] as List).map((t) {
              final m = t as Map<String,dynamic>;
              return Card(child: ListTile(
                dense: true,
                leading: SevChip(str(m['severity'])),
                title: Text(str(m['name'] ?? m['type']), style: const TextStyle(fontSize: 13)),
                trailing: Text(str(m['count'] ?? 0), style: const TextStyle(fontWeight: FontWeight.bold)),
              ));
            }),
          ],
        ],
      ),
    );
  }

  Widget _trendCard(String title, List data) {
    final max = data.fold<num>(1, (m, v) => m > ((v as Map)['count'] as num? ?? 0) ? m : (v['count'] as num? ?? 0));
    return Card(child: Padding(
      padding: const EdgeInsets.all(12),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 13)),
        const SizedBox(height: 8),
        Row(
          crossAxisAlignment: CrossAxisAlignment.end,
          children: data.map((d) {
            final m     = d as Map<String,dynamic>;
            final count = (m['count'] as num? ?? 0).toDouble();
            final h     = 60 * count / max;
            return Expanded(child: Column(mainAxisSize: MainAxisSize.min, children: [
              Text('${m['count'] ?? 0}', style: const TextStyle(fontSize: 9, color: Colors.grey)),
              Container(margin: const EdgeInsets.symmetric(horizontal: 2), height: h.clamp(4, 60), color: Colors.blue),
              Text(str(m['label'] ?? m['date'] ?? '').length > 4 ? str(m['label'] ?? '').substring(str(m['label'] ?? '').length - 4) : str(m['label'] ?? ''), style: const TextStyle(fontSize: 8, color: Colors.grey)),
            ]));
          }).toList(),
        ),
      ]),
    ));
  }
}

// ── SOC Metrics ───────────────────────────────────────────────────────────────

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
    final r = await widget.api.socMetrics();
    if (!mounted) return;
    setState(() { _data = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final d = _data ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          const Text('DETECTION', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
          const SizedBox(height: 8),
          StatRow([
            ('MTTD (min)',    str(d['mean_time_to_detect_min'] ?? d['mttd'] ?? 'N/A'),    Colors.blue),
            ('Detection Rate','${d['detection_rate'] ?? 0}%',                              Colors.green),
          ]),
          const SizedBox(height: 4),
          const Text('RESPONSE', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
          const SizedBox(height: 8),
          StatRow([
            ('MTTR (min)',    str(d['mean_time_to_respond_min'] ?? d['mttr'] ?? 'N/A'),   Colors.orange),
            ('False Positive','${d['false_positive_rate'] ?? 0}%',                         Colors.red),
          ]),
          const SizedBox(height: 4),
          const Text('VOLUME', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
          const SizedBox(height: 8),
          StatRow([
            ('Alerts (24h)',  str(d['alerts_24h'] ?? 0),  Colors.purple),
            ('Events/sec',    str(d['events_per_second'] ?? d['eps'] ?? 0), Colors.teal),
          ]),
          if (d['analyst_performance'] is List) ...[
            const SizedBox(height: 12),
            const Text('ANALYST PERFORMANCE', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
            const SizedBox(height: 8),
            ...(d['analyst_performance'] as List).map((a) {
              final m = a as Map<String,dynamic>;
              return Card(child: ListTile(
                dense: true,
                leading: CircleAvatar(radius: 16, backgroundColor: Colors.blue.shade800, child: Text(str(m['name']).substring(0,1), style: const TextStyle(color: Colors.white, fontSize: 12))),
                title: Text(str(m['name']), style: const TextStyle(fontSize: 13)),
                trailing: Text('${m['closed']} closed  ·  MTTR ${m['mttr']}m', style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ));
            }),
          ],
        ],
      ),
    );
  }
}

// ── Risk Posture ──────────────────────────────────────────────────────────────

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
    final r = await widget.api.riskPosture();
    if (!mounted) return;
    setState(() { _data = r; _loading = false; });
  }

  String _label(num v) {
    if (v >= 80) return 'CRITICAL';
    if (v >= 60) return 'HIGH';
    if (v >= 40) return 'MEDIUM';
    return 'LOW';
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final d = _data ?? {};
    final score = (d['overall_score'] ?? d['risk_score'] ?? 0) as num;
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Card(child: Padding(
            padding: const EdgeInsets.all(16),
            child: Column(children: [
              Text('OVERALL RISK', style: TextStyle(color: sevColor(_label(score).toLowerCase()), fontSize: 11, letterSpacing: 1.5)),
              const SizedBox(height: 8),
              Text('${score.round()}', style: TextStyle(fontSize: 56, fontWeight: FontWeight.bold, color: sevColor(_label(score).toLowerCase()))),
              Text(_label(score), style: TextStyle(color: sevColor(_label(score).toLowerCase()), fontWeight: FontWeight.w600)),
              const SizedBox(height: 10),
              LinearProgressIndicator(
                value: score / 100,
                backgroundColor: Colors.grey.shade300,
                color: sevColor(_label(score).toLowerCase()),
                minHeight: 8,
              ),
            ]),
          )),
          const SizedBox(height: 8),
          if (d['category_scores'] is Map) ...[
            const Text('BY CATEGORY', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
            const SizedBox(height: 8),
            ...(d['category_scores'] as Map).entries.map((e) {
              final catScore = (e.value as num).toDouble();
              return Card(child: Padding(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Text(e.key.toString(), style: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13)),
                    const Spacer(),
                    Text('${catScore.round()}', style: TextStyle(fontWeight: FontWeight.bold, color: sevColor(_label(catScore).toLowerCase()))),
                  ]),
                  const SizedBox(height: 6),
                  LinearProgressIndicator(value: catScore / 100, backgroundColor: Colors.grey.shade300, color: sevColor(_label(catScore).toLowerCase()), minHeight: 5),
                ]),
              ));
            }),
          ] else ...[
            StatRow([
              ('Vulnerabilities', str(d['vuln_score'] ?? 0),        Colors.red),
              ('Compliance',      str(d['compliance_score'] ?? 0),   Colors.blue),
            ]),
            StatRow([
              ('Exposure',        str(d['exposure_score'] ?? 0),     Colors.orange),
              ('Threat Intel',    str(d['threat_score'] ?? 0),       Colors.purple),
            ]),
          ],
          if (d['top_risks'] is List) ...[
            const SizedBox(height: 12),
            const Text('TOP RISKS', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
            const SizedBox(height: 6),
            ...(d['top_risks'] as List).map((r) {
              final m = r as Map<String,dynamic>;
              return Card(child: ListTile(
                leading: SevChip(str(m['severity'])),
                title: Text(str(m['title'] ?? m['name']), style: const TextStyle(fontSize: 13)),
                subtitle: Text(str(m['description'] ?? ''), maxLines: 1, overflow: TextOverflow.ellipsis),
              ));
            }),
          ],
        ],
      ),
    );
  }
}
