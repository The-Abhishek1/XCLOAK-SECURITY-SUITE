import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// OT/ICS — real industrial-control-systems dashboard backed by /api/ot/*
// (api/ot_ics_enterprise.go). Was previously showing nothing at all: the
// shared ItdrScreen filtered /api/itdr/findings by type='ot_ics', a value
// that column never actually holds (only brute_force/credential_theft/
// mfa_gap etc.), so the query always matched zero rows.
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

Color _riskColor(num score) => score >= 70 ? _kRed : score >= 40 ? _kAmber : _kGreen;

class OTICSScreen extends StatefulWidget {
  final DashboardApi api;
  const OTICSScreen({super.key, required this.api});
  @override State<OTICSScreen> createState() => _OTICSState();
}

class _OTICSState extends State<OTICSScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 13, vsync: this);

  Map<String,dynamic>? _dashboard, _topology, _protocols, _alerts, _devices,
      _threats, _dpi, _risk, _vulns, _zones, _baseline, _threatIntel,
      _compliance, _attackPaths, _analytics;
  List _assets = [], _traffic = [], _timeline = [];
  bool _loading = true;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.otDashboard(),
      widget.api.otAssets(),
      widget.api.otTopology(),
      widget.api.otProtocols(),
      widget.api.otTraffic(),
      widget.api.otAlerts(),
      widget.api.otDevices(),
      widget.api.otThreats(),
      widget.api.otDPI(),
      widget.api.otRisk(),
      widget.api.otVulnerabilities(),
      widget.api.otZones(),
      widget.api.otBaseline(),
      widget.api.otThreatIntel(),
      widget.api.otTimeline(),
      widget.api.otCompliance(),
      widget.api.otAttackPaths(),
      widget.api.otAnalytics(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard   = r[0]  as Map<String,dynamic>?;
      _assets      = r[1]  as List;
      _topology    = r[2]  as Map<String,dynamic>?;
      _protocols   = r[3]  as Map<String,dynamic>?;
      _traffic     = r[4]  as List;
      _alerts      = r[5]  as Map<String,dynamic>?;
      _devices     = r[6]  as Map<String,dynamic>?;
      _threats     = r[7]  as Map<String,dynamic>?;
      _dpi         = r[8]  as Map<String,dynamic>?;
      _risk        = r[9]  as Map<String,dynamic>?;
      _vulns       = r[10] as Map<String,dynamic>?;
      _zones       = r[11] as Map<String,dynamic>?;
      _baseline    = r[12] as Map<String,dynamic>?;
      _threatIntel = r[13] as Map<String,dynamic>?;
      _timeline    = r[14] as List;
      _compliance  = r[15] as Map<String,dynamic>?;
      _attackPaths = r[16] as Map<String,dynamic>?;
      _analytics   = r[17] as Map<String,dynamic>?;
      _loading     = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Assets'), Tab(text: 'Network'),
        Tab(text: 'Alerts'), Tab(text: 'Devices'), Tab(text: 'Threats'),
        Tab(text: 'Risk'), Tab(text: 'Zones'), Tab(text: 'Baseline'),
        Tab(text: 'Intelligence'), Tab(text: 'Compliance'),
        Tab(text: 'Attack Paths'), Tab(text: 'Analytics'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _assetsTab(), _networkTab(), _alertsTab(), _devicesTab(),
        _threatsTab(), _riskTab(), _zonesTab(), _baselineTab(), _intelTab(),
        _complianceTab(), _attackPathsTab(), _analyticsTab(),
      ])),
    ]);
  }

  // ── Overview ────────────────────────────────────────────────────────────
  Widget _overviewTab() {
    final d = _dashboard ?? {};
    final alerts = (_alerts?['alerts'] as List?) ?? [];
    final criticalAssets = (_risk?['critical_assets'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Sites', value: str(d['sites'], '0'), color: _kBlue, icon: Icons.factory_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Zones', value: str(d['industrial_zones'], '0'), color: _kPurple, icon: Icons.grid_view)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'PLCs', value: str(d['plcs'], '0'), color: _kBlue, icon: Icons.memory)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'HMIs', value: str(d['hmis'], '0'), color: _kBlue, icon: Icons.desktop_windows_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'RTUs', value: str(d['rtus'], '0'), color: _kBlue, icon: Icons.router_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Eng. Workstations', value: str(d['engineering_workstations'], '0'), color: _kBlue, icon: Icons.engineering_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'SCADA Servers', value: str(d['scada_servers'], '0'), color: _kBlue, icon: Icons.dns_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Total Assets', value: str(d['total_assets'], '0'), color: _kGreen, icon: Icons.storage)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'OT Risk Score', value: str(d['ot_risk_score'], '0'), color: _kAmber, icon: Icons.speed)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Critical Alerts', value: str(d['critical_alerts'], '0'), color: _kRed, icon: Icons.warning_amber)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Active Incidents', value: str(d['active_incidents'], '0'), color: _kRed, icon: Icons.report_problem_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Network Health', value: '${str(d['network_health'], '0')}%', color: _kGreen, icon: Icons.health_and_safety_outlined)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Recent Alerts'),
      const SizedBox(height: 8),
      if (alerts.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No OT alerts recorded', style: TextStyle(color: Colors.grey)))
      else ...alerts.take(5).map((a) {
        final m = a as Map<String,dynamic>;
        return _tile(icon: Icons.notifications_active_outlined, iconColor: sevColor(str(m['severity'])),
          title: str(m['title']), subtitle: '${str(m['protocol'])} · ${str(m['src_ip'])}',
          trailing: timeAgo(m['created_at']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Top Risk Assets'),
      const SizedBox(height: 8),
      if (criticalAssets.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No assets above the risk threshold', style: TextStyle(color: Colors.grey)))
      else ...criticalAssets.map((a) {
        final m = a as Map<String,dynamic>;
        return _tile(icon: Icons.warning_amber, iconColor: _riskColor((m['risk'] as num?) ?? 0),
          title: str(m['name']), subtitle: str(m['reason']), trailing: '${str(m['risk'],'0')}');
      }),
    ]));
  }

  // ── Assets ──────────────────────────────────────────────────────────────
  Widget _assetsTab() {
    if (_assets.isEmpty) return const XEmptyState('No OT assets discovered', icon: Icons.precision_manufacturing_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _assets.length,
      itemBuilder: (_, i) {
        final a = _assets[i] as Map<String,dynamic>;
        final online = a['is_online'] == true;
        final risk = (a['risk_score'] as num?) ?? 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: Theme.of(context).colorScheme.outlineVariant)),
          child: Row(children: [
            Container(width: 8, height: 8, margin: const EdgeInsets.only(right: 10),
              decoration: BoxDecoration(shape: BoxShape.circle, color: online ? _kGreen : Colors.grey)),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(a['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              Text('${str(a['asset_type']).replaceAll('_', ' ')} · ${str(a['vendor'])} ${str(a['model'],'')} · ${str(a['ip'])}',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
              Text('${str(a['zone'])} / ${str(a['site'])} · Purdue L${str(a['purdue_level'],'0')} · ${str(a['criticality']).toUpperCase()}',
                style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            ])),
            Text('${str(a['risk_score'], '0')}', style: TextStyle(fontWeight: FontWeight.w800, color: _riskColor(risk))),
          ]),
        );
      },
    ));
  }

  // ── Network (topology + protocols + traffic) ───────────────────────────
  Widget _networkTab() {
    final nodes = (_topology?['nodes'] as List?) ?? [];
    final links = (_topology?['links'] as List?) ?? [];
    final protoStats = (_protocols?['protocol_stats'] as List?) ?? [];
    final supported = (_protocols?['supported_protocols'] as List?) ?? [];
    final sessions = (_protocols?['sessions'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Nodes', value: '${nodes.length}', color: _kBlue, icon: Icons.device_hub)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Links', value: '${links.length}', color: _kPurple, icon: Icons.call_split)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Protocol Traffic'),
      const SizedBox(height: 8),
      if (protoStats.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No protocol traffic observed', style: TextStyle(color: Colors.grey)))
      else ...protoStats.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.swap_horiz, title: str(m['protocol']), trailing: str(m['count']));
      }),
      const SizedBox(height: 8),
      Wrap(spacing: 6, runSpacing: 6, children: supported.map((p) => _Pill(label: str(p), color: _kBlue)).toList()),
      const SizedBox(height: 16),
      SectionTitle('Active Sessions'),
      const SizedBox(height: 8),
      if (sessions.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No active sessions', style: TextStyle(color: Colors.grey)))
      else ...sessions.map((s) {
        final m = s as Map<String,dynamic>;
        final anomaly = str(m['anomaly'], '');
        return _tile(icon: Icons.compare_arrows, iconColor: anomaly.isNotEmpty ? _kRed : Colors.grey,
          title: '${str(m['src'])} → ${str(m['dst'])}',
          subtitle: '${str(m['protocol'])} · ${str(m['packets'],'0')} packets${anomaly.isNotEmpty ? " · $anomaly" : ""}',
          trailing: timeAgo(m['last_seen']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Network Links'),
      const SizedBox(height: 8),
      if (links.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No network links recorded', style: TextStyle(color: Colors.grey)))
      else ...links.map((l) {
        final m = l as Map<String,dynamic>;
        final active = m['active'] == true;
        return _tile(icon: Icons.link, iconColor: active ? _kGreen : Colors.grey,
          title: '${str(m['src'])} → ${str(m['dst'])}', subtitle: str(m['protocol']),
          trailing: active ? 'active' : 'idle');
      }),
      const SizedBox(height: 16),
      SectionTitle('Raw Traffic'),
      const SizedBox(height: 8),
      if (_traffic.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No raw traffic captured', style: TextStyle(color: Colors.grey)))
      else ..._traffic.take(30).map((t) {
        final m = t as Map<String,dynamic>;
        final unauthorized = m['is_authorized'] != true;
        return _tile(icon: Icons.data_object, iconColor: unauthorized ? _kRed : sevColor(str(m['severity'])),
          title: '${str(m['operation'])} ${str(m['register_addr'])} = ${str(m['value'])}'.trim(),
          subtitle: '${str(m['src_ip'])} → ${str(m['dst_ip'])} · ${str(m['protocol'])} · ${str(m['function_code'])}${unauthorized ? " · UNAUTHORIZED" : ""}',
          trailing: timeAgo(m['created_at']));
      }),
    ]));
  }

  // ── Alerts ──────────────────────────────────────────────────────────────
  Widget _alertsTab() {
    final list = (_alerts?['alerts'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Total', value: str(_alerts?['total'], '0'), color: _kBlue, icon: Icons.notifications_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Open', value: str(_alerts?['open'], '0'), color: _kAmber, icon: Icons.mark_email_unread_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Critical', value: str(_alerts?['critical'], '0'), color: _kRed, icon: Icons.priority_high)),
      ]),
      const SizedBox(height: 16),
      if (list.isEmpty) const XEmptyState('No OT alerts', icon: Icons.verified_user_outlined)
      else ...list.map((a) {
        final m = a as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['title']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['alert_type']).replaceAll('_', ' ')} · ${str(m['protocol'])} · ${str(m['src_ip'])} · ${str(m['status'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['description']).isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(str(m['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 8),
            Row(children: [
              TextButton(onPressed: () => _respond('create_incident', str(m['title']), str(m['description'])),
                child: const Text('Create Incident', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('block_network_path', str(m['src_ip']), str(m['title'])),
                child: const Text('Block Path', style: TextStyle(fontSize: 11))),
            ]),
          ]),
        );
      }),
    ]));
  }

  Future<void> _respond(String action, String target, String reason) async {
    final res = await widget.api.otRespond({'action': action, 'target': target, 'reason': reason});
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  // ── Devices ─────────────────────────────────────────────────────────────
  Widget _devicesTab() {
    final devices = (_devices?['devices'] as List?) ?? [];
    final fwChanges = (_devices?['firmware_changes'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Device Status'),
      const SizedBox(height: 8),
      if (devices.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No devices discovered', style: TextStyle(color: Colors.grey)))
      else ...devices.map((d) {
        final m = d as Map<String,dynamic>;
        final online = m['is_online'] == true;
        return _tile(icon: online ? Icons.check_circle_outline : Icons.cancel_outlined,
          iconColor: online ? _kGreen : Colors.grey,
          title: str(m['name']),
          subtitle: '${str(m['asset_type']).replaceAll('_', ' ')} · ${str(m['ip'])} · fw ${str(m['firmware'])} · ${str(m['zone'])}',
          trailing: online ? '${str(m['uptime_hours'],'0')}h up' : timeAgo(m['last_seen']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Firmware Changes'),
      const SizedBox(height: 8),
      if (fwChanges.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No firmware changes recorded', style: TextStyle(color: Colors.grey)))
      else ...fwChanges.map((f) {
        final m = f as Map<String,dynamic>;
        final authorized = m['is_authorized'] == true;
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Icon(Icons.system_update_outlined, size: 16, color: authorized ? _kGreen : _kRed),
            const SizedBox(width: 10),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text('${str(m['previous_version'])} → ${str(m['firmware_version'])}',
                style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
              Text('by ${str(m['changed_by'])} · ${timeAgo(m['changed_at'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ])),
            _Pill(label: authorized ? 'AUTHORIZED' : 'UNAUTHORIZED', color: authorized ? _kGreen : _kRed),
          ]),
        );
      }),
    ]));
  }

  // ── Threats (threats + DPI + vulnerabilities) ──────────────────────────
  Widget _threatsTab() {
    final threats = (_threats?['threats'] as List?) ?? [];
    final categories = (_threats?['detection_categories'] as List?) ?? [];
    final frames = (_dpi?['decoded_frames'] as List?) ?? [];
    final vulns = (_vulns?['vulns'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Active Threats'),
      const SizedBox(height: 8),
      if (threats.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No active OT threats', style: TextStyle(color: Colors.grey)))
      else ...threats.map((t) {
        final m = t as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['title']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['alert_type']).replaceAll('_', ' ')} · ${str(m['protocol'])} · ${str(m['src_ip'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ]),
        );
      }),
      const SizedBox(height: 8),
      Wrap(spacing: 6, runSpacing: 6,
        children: categories.map((c) => _Pill(label: str(c).replaceAll('_', ' '), color: _kPurple)).toList()),
      const SizedBox(height: 16),
      SectionTitle('Deep Packet Inspection'),
      const SizedBox(height: 8),
      if (frames.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No decoded frames', style: TextStyle(color: Colors.grey)))
      else ...frames.take(20).map((f) {
        final m = f as Map<String,dynamic>;
        final unauthorized = m['is_authorized'] != true;
        return _tile(icon: Icons.code, iconColor: unauthorized ? _kRed : Colors.grey,
          title: '${str(m['protocol'])} ${str(m['function_code'])}: ${str(m['operation'])} ${str(m['register_addr'])}',
          subtitle: '${str(m['src_ip'])} → ${str(m['dst_ip'])} = ${str(m['value'])}',
          trailing: timeAgo(m['created_at']));
      }),
      const SizedBox(height: 16),
      Row(children: [
        Expanded(child: KpiCard(label: 'Critical Vulns', value: str(_vulns?['critical'], '0'), color: _kRed, icon: Icons.bug_report_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'High Vulns', value: str(_vulns?['high'], '0'), color: _kOrange, icon: Icons.bug_report_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Patchable', value: str(_vulns?['patchable'], '0'), color: _kGreen, icon: Icons.build_outlined)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Vulnerabilities'),
      const SizedBox(height: 8),
      if (vulns.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No known vulnerabilities on OT assets', style: TextStyle(color: Colors.grey)))
      else ...vulns.map((v) {
        final m = v as Map<String,dynamic>;
        final sev = str(m['severity']);
        return _tile(icon: Icons.warning_amber, iconColor: sevColor(sev),
          title: '${str(m['cve_id'])} · ${str(m['title'])}',
          subtitle: '${str(m['vendor_advisory'])} · CVSS ${str(m['cvss'])}${m['patch_available'] == true ? " · patch available" : ""}',
          trailing: sev.toUpperCase());
      }),
    ]));
  }

  // ── Risk ────────────────────────────────────────────────────────────────
  Widget _riskTab() {
    final r = _risk ?? {};
    final critical = (r['critical_assets'] as List?) ?? [];
    final findings = (r['findings'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Assets', value: str(r['total_assets'], '0'), color: _kBlue, icon: Icons.storage)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Internet Exposed', value: str(r['internet_exposed'], '0'), color: _kRed, icon: Icons.public)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'EOL Firmware', value: str(r['unsupported_firmware'], '0'), color: _kOrange, icon: Icons.memory)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'No Segmentation', value: str(r['missing_segmentation'], '0'), color: _kAmber, icon: Icons.security)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Findings'),
      const SizedBox(height: 8),
      if (findings.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No open risk findings', style: TextStyle(color: Colors.grey)))
      else ...findings.map((f) {
        final m = f as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['category']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text(str(m['detail']), style: const TextStyle(fontSize: 11.5)),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Critical Assets'),
      const SizedBox(height: 8),
      if (critical.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No assets above the risk threshold', style: TextStyle(color: Colors.grey)))
      else ...critical.map((a) {
        final m = a as Map<String,dynamic>;
        return _tile(icon: Icons.warning_amber, iconColor: _riskColor((m['risk'] as num?) ?? 0),
          title: '${str(m['name'])} (${str(m['type'])})', subtitle: '${str(m['ip'])} · ${str(m['reason'])}',
          trailing: '${str(m['risk'],'0')}');
      }),
    ]));
  }

  // ── Zones ───────────────────────────────────────────────────────────────
  Widget _zonesTab() {
    final z = _zones ?? {};
    final zones = (z['zones'] as List?) ?? [];
    final purdue = (z['purdue_model'] as List?) ?? [];
    final paths = (z['allowed_paths'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Segmentation Zones'),
      const SizedBox(height: 8),
      if (zones.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No segmentation zones configured', style: TextStyle(color: Colors.grey)))
      else ...zones.map((zn) {
        final m = zn as Map<String,dynamic>;
        final noPolicy = str(m['firewall_policy']).isEmpty || str(m['firewall_policy']) == '—';
        return _tile(icon: Icons.shield_outlined, iconColor: noPolicy ? _kRed : _kGreen,
          title: '${str(m['name'])} (L${str(m['purdue_level'],'0')})',
          subtitle: '${str(m['asset_count'],'0')} assets · ${str(m['allowed_protocols'])}',
          trailing: noPolicy ? 'NO POLICY' : str(m['firewall_policy']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Purdue Model Reference'),
      const SizedBox(height: 8),
      ...purdue.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.layers_outlined, title: 'L${str(m['level'])} · ${str(m['name'])}',
          subtitle: str(m['description']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Allowed Paths'),
      const SizedBox(height: 8),
      ...paths.map((p) {
        final m = p as Map<String,dynamic>;
        final allowed = m['allowed'] == true;
        return _tile(icon: allowed ? Icons.check : Icons.block, iconColor: allowed ? _kGreen : _kRed,
          title: 'L${str(m['from_level'])} → L${str(m['to_level'])}',
          subtitle: str(m['protocols'], allowed ? '' : 'blocked'),
          trailing: m['requires_firewall'] == true ? 'firewall req.' : '');
      }),
    ]));
  }

  // ── Baseline ────────────────────────────────────────────────────────────
  Widget _baselineTab() {
    final b = _baseline ?? {};
    final categories = (b['categories'] as List?) ?? [];
    final baselines = (b['baselines'] as List?) ?? [];
    final deviations = (b['deviations'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Baseline Categories'),
      const SizedBox(height: 8),
      if (categories.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No baselines learned yet', style: TextStyle(color: Colors.grey)))
      else ...categories.map((c) {
        final m = c as Map<String,dynamic>;
        final learned = m['learned'] == true;
        return _tile(icon: learned ? Icons.check_circle_outline : Icons.hourglass_empty,
          iconColor: learned ? _kGreen : Colors.grey,
          title: str(m['type']).replaceAll('_', ' '), trailing: '${str(m['items'],'0')} items');
      }),
      const SizedBox(height: 16),
      SectionTitle('Learned Baselines'),
      const SizedBox(height: 8),
      if (baselines.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No baseline entries', style: TextStyle(color: Colors.grey)))
      else ...baselines.map((bl) {
        final m = bl as Map<String,dynamic>;
        return _tile(icon: Icons.tune, title: str(m['baseline_type']).replaceAll('_', ' '),
          subtitle: str(m['description']),
          trailing: m['is_active'] == true ? 'active' : 'inactive');
      }),
      const SizedBox(height: 16),
      SectionTitle('Deviations'),
      const SizedBox(height: 8),
      if (deviations.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No baseline deviations detected', style: TextStyle(color: Colors.grey)))
      else ...deviations.map((dv) {
        final m = dv as Map<String,dynamic>;
        return _tile(icon: Icons.change_history, iconColor: sevColor(str(m['severity'])),
          title: str(m['detail']), subtitle: str(m['type']).replaceAll('_', ' '), trailing: timeAgo(m['time']));
      }),
    ]));
  }

  // ── Threat Intelligence ─────────────────────────────────────────────────
  Widget _intelTab() {
    final ti = _threatIntel ?? {};
    final iocs = (ti['ioc_matches'] as List?) ?? [];
    final actors = (ti['ot_threat_actors'] as List?) ?? [];
    final malware = (ti['industrial_malware'] as List?) ?? [];
    final advisories = (ti['sector_advisories'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('IOC Matches'),
      const SizedBox(height: 8),
      if (iocs.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No indicator matches against OT traffic/assets', style: TextStyle(color: Colors.grey)))
      else ...iocs.map((i) {
        final m = i as Map<String,dynamic>;
        return _tile(icon: Icons.gps_fixed, iconColor: _kRed, title: str(m['value']),
          subtitle: str(m['type']).toUpperCase(), trailing: '${str(m['hits'])} hits');
      }),
      const SizedBox(height: 16),
      SectionTitle('OT Threat Actors'),
      const SizedBox(height: 8),
      ...actors.map((a) {
        final m = a as Map<String,dynamic>;
        final risk = str(m['risk']);
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Icon(Icons.groups_outlined, size: 16, color: sevColor(risk)),
            const SizedBox(width: 10),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Text(str(m['name']), style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700)),
                const SizedBox(width: 6),
                if (m['active'] == true) const _Pill(label: 'ACTIVE', color: _kRed),
              ]),
              Text('${str(m['nation'])} · ${str(m['targets'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
              Text(str(m['malware']), style: const TextStyle(fontSize: 10.5, color: _kPurple)),
            ])),
            _Pill(label: risk.toUpperCase(), color: sevColor(risk)),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Industrial Malware'),
      const SizedBox(height: 8),
      ...malware.map((m0) {
        final m = m0 as Map<String,dynamic>;
        return _tile(icon: Icons.bug_report_outlined, title: '${str(m['name'])} (${str(m['year'])})',
          subtitle: '${str(m['type'])} · ${str(m['target'])}', trailing: '');
      }),
      const SizedBox(height: 16),
      SectionTitle('Sector Advisories'),
      const SizedBox(height: 8),
      ...advisories.map((a) {
        final m = a as Map<String,dynamic>;
        final sev = str(m['severity']);
        return _tile(icon: Icons.campaign_outlined, iconColor: sevColor(sev),
          title: str(m['title']), subtitle: '${str(m['id'])} · ${str(m['affected'])}', trailing: str(m['date']));
      }),
    ]));
  }

  // ── Compliance ──────────────────────────────────────────────────────────
  Widget _complianceTab() {
    final c = _compliance ?? {};
    final frameworks = (c['frameworks'] as List?) ?? [];
    final failedControls = (c['failed_controls'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Overall Score', value: '${str(c['overall_score'], '0')}%', color: _kGreen, icon: Icons.verified_user)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Frameworks'),
      const SizedBox(height: 8),
      if (frameworks.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No compliance frameworks tracked for OT', style: TextStyle(color: Colors.grey)))
      else ...frameworks.map((f) {
        final m = f as Map<String,dynamic>;
        final score = (m['score'] as num?)?.toDouble() ?? 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 10), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text('${score.toStringAsFixed(0)}%', style: TextStyle(fontWeight: FontWeight.w800, color: _riskColor(100 - score))),
            ]),
            const SizedBox(height: 6),
            ClipRRect(borderRadius: BorderRadius.circular(4), child: LinearProgressIndicator(
              value: score / 100, minHeight: 6,
              backgroundColor: _kRed.withValues(alpha: .15),
              valueColor: AlwaysStoppedAnimation(_riskColor(100 - score)))),
            const SizedBox(height: 4),
            Text('${str(m['passed'],'0')} passed / ${str(m['failed'],'0')} failed of ${str(m['total'],'0')} · ${str(m['status'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Failed Controls'),
      const SizedBox(height: 8),
      if (failedControls.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No failed controls', style: TextStyle(color: Colors.grey)))
      else ...failedControls.map((ctl) {
        final m = ctl as Map<String,dynamic>;
        return _tile(icon: Icons.rule, iconColor: sevColor(str(m['severity'])),
          title: '${str(m['control'])} · ${str(m['title'])}', subtitle: str(m['framework']), trailing: str(m['severity']).toUpperCase());
      }),
    ]));
  }

  // ── Attack Paths ────────────────────────────────────────────────────────
  Widget _attackPathsTab() {
    final riskAssets = (_attackPaths?['risk_assets'] as List?) ?? [];
    final exposedVulns = (_attackPaths?['exposed_control_vulns'] as List?) ?? [];
    if (riskAssets.isEmpty && exposedVulns.isEmpty) {
      return const XEmptyState('No attack paths identified', icon: Icons.route_outlined);
    }
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Highest-Risk Assets'),
      const SizedBox(height: 8),
      if (riskAssets.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No risk-ranked assets', style: TextStyle(color: Colors.grey)))
      else ...riskAssets.map((a) {
        final m = a as Map<String,dynamic>;
        return _tile(icon: Icons.device_hub, iconColor: _riskColor((m['risk_score'] as num?) ?? 0),
          title: str(m['name']),
          subtitle: '${str(m['asset_type']).replaceAll('_', ' ')} · ${str(m['ip'])} · ${str(m['zone'])} · L${str(m['purdue_level'],'0')}',
          trailing: '${str(m['risk_score'],'0')}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Exposed Control-Layer Vulnerabilities'),
      const SizedBox(height: 8),
      if (exposedVulns.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No exposed vulnerabilities on Purdue L0/L1 assets', style: TextStyle(color: Colors.grey)))
      else ...exposedVulns.map((v) {
        final m = v as Map<String,dynamic>;
        return _tile(icon: Icons.link, iconColor: sevColor(str(m['severity'])),
          title: '${str(m['cve_id'])} on ${str(m['asset'])}', subtitle: 'CVSS ${str(m['cvss'])}',
          trailing: str(m['severity']).toUpperCase());
      }),
    ]));
  }

  // ── Analytics (+ timeline) ──────────────────────────────────────────────
  Widget _analyticsTab() {
    final a = _analytics ?? {};
    final plcs = (a['most_active_plcs'] as List?) ?? [];
    final protoDist = (a['protocol_distribution'] as List?) ?? [];
    final configChanges = (a['config_changes_7d'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Most Active PLCs/RTUs'),
      const SizedBox(height: 8),
      if (plcs.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No PLC/RTU command activity', style: TextStyle(color: Colors.grey)))
      else ...plcs.map((p) {
        final m = p as Map<String,dynamic>;
        final anomalies = (m['anomalies'] as num?) ?? 0;
        return _tile(icon: Icons.memory, iconColor: anomalies > 0 ? _kRed : Colors.grey,
          title: str(m['name']),
          subtitle: '${str(m['commands'],'0')} commands · ${str(m['writes'],'0')} writes · ${str(m['reads'],'0')} reads',
          trailing: anomalies > 0 ? '$anomalies anomalies' : 'clean');
      }),
      const SizedBox(height: 16),
      SectionTitle('Protocol Distribution'),
      const SizedBox(height: 8),
      if (protoDist.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No protocol traffic recorded', style: TextStyle(color: Colors.grey)))
      else ...protoDist.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.pie_chart_outline, title: str(m['protocol']), trailing: '${str(m['percent'],'0')}%');
      }),
      const SizedBox(height: 16),
      SectionTitle('Firmware/Config Changes (7d)'),
      const SizedBox(height: 8),
      ...configChanges.map((c) {
        final m = c as Map<String,dynamic>;
        return _tile(icon: Icons.event_note_outlined, title: str(m['day']), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Event Timeline'),
      const SizedBox(height: 8),
      if (_timeline.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No timeline events', style: TextStyle(color: Colors.grey)))
      else ..._timeline.map((e) {
        final m = e as Map<String,dynamic>;
        return _tile(icon: Icons.history, iconColor: sevColor(str(m['severity'])),
          title: str(m['title']), subtitle: '${str(m['event_type']).replaceAll('_', ' ')} · ${str(m['source'])} · ${str(m['status'])}',
          trailing: timeAgo(m['created_at']));
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
        if (trailing != null && trailing.isNotEmpty) Text(trailing, style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
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
