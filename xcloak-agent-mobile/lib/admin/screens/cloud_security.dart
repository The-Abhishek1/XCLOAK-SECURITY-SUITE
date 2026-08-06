import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Cloud Security — real multi-cloud CSPM/CIEM/threat-detection dashboard
// backed by /api/cloud/* (api/cloud_security_enterprise.go). Was previously
// showing nothing at all: the shared ItdrScreen filtered /api/itdr/findings
// by type='cloud', a value that column never actually holds.
// ─────────────────────────────────────────────────────────────────────────────

const _kRed    = Color(0xFFEF4444);
const _kOrange = Color(0xFFF97316);
const _kAmber  = Color(0xFFF59E0B);
const _kBlue   = Color(0xFF3B82F6);
const _kGreen  = Color(0xFF22C55E);
const _kPurple = Color(0xFF8B5CF6);
// sevColor(String) is already exported by ../widgets.dart — reused here,
// not redeclared, so every screen in this app maps severity to color
// identically (including the unrecognized-value fallback).

class CloudSecurityScreen extends StatefulWidget {
  final DashboardApi api;
  const CloudSecurityScreen({super.key, required this.api});
  @override State<CloudSecurityScreen> createState() => _CloudSecurityState();
}

class _CloudSecurityState extends State<CloudSecurityScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 9, vsync: this);

  Map<String,dynamic>? _dashboard;
  List _accounts = [], _inventory = [], _findings = [], _cspmSummary = [],
       _identities = [], _threats = [], _compliance = [], _drift = [],
       _vulns = [];
  Map<String,dynamic>? _ciemRisks, _exposure, _attackPaths, _threatIntel, _analytics;
  bool _loading = true;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.cloudDashboard(),
      widget.api.cloudAccounts(),
      widget.api.cloudInventory(),
      widget.api.cloudCSPMFindings(),
      widget.api.cloudCSPMSummary(),
      widget.api.cloudIdentities(),
      widget.api.cloudCIEMRisks(),
      widget.api.cloudThreats(),
      widget.api.cloudExposure(),
      widget.api.cloudCompliance(),
      widget.api.cloudAttackPaths(),
      widget.api.cloudDrift(),
      widget.api.cloudVulnerabilities(),
      widget.api.cloudThreatIntel(),
      widget.api.cloudAnalytics(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard   = r[0]  as Map<String,dynamic>?;
      _accounts    = r[1]  as List;
      _inventory   = r[2]  as List;
      _findings    = r[3]  as List;
      _cspmSummary = r[4]  as List;
      _identities  = r[5]  as List;
      _ciemRisks   = r[6]  as Map<String,dynamic>?;
      _threats     = r[7]  as List;
      _exposure    = r[8]  as Map<String,dynamic>?;
      _compliance  = r[9]  as List;
      _attackPaths = r[10] as Map<String,dynamic>?;
      _drift       = r[11] as List;
      _vulns       = r[12] as List;
      _threatIntel = r[13] as Map<String,dynamic>?;
      _analytics   = r[14] as Map<String,dynamic>?;
      _loading     = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Inventory'), Tab(text: 'CSPM'),
        Tab(text: 'CIEM'), Tab(text: 'Detection'), Tab(text: 'Compliance'),
        Tab(text: 'Attack Paths'), Tab(text: 'Intelligence'), Tab(text: 'Analytics'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _inventoryTab(), _cspmTab(), _ciemTab(), _detectionTab(),
        _complianceTab(), _attackPathsTab(), _intelTab(), _analyticsTab(),
      ])),
    ]);
  }

  void _addAccount() {
    final nameCtrl = TextEditingController();
    final idCtrl   = TextEditingController();
    String provider = 'aws';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Connect Cloud Account'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Provider', provider, ['aws','azure','gcp'], (v) => ss(() => provider = v!)),
          const SizedBox(height: 10),
          xField(idCtrl, 'Account ID'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createCloudAccount({
                'name': nameCtrl.text.trim(), 'provider': provider, 'account_id': idCtrl.text.trim(),
              });
              if (context.mounted) xSnack(context, ok ? 'Account connected' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Connect'),
          )),
        ]),
      )),
    );
  }

  Widget _overviewTab() {
    final d = _dashboard ?? {};
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'AWS', value: str(d['aws_accounts'], '0'), color: _kOrange, icon: Icons.cloud)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Azure', value: str(d['azure_subs'], '0'), color: _kBlue, icon: Icons.cloud)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'GCP', value: str(d['gcp_projects'], '0'), color: _kGreen, icon: Icons.cloud)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Assets', value: str(d['total_assets'], '0'), color: _kBlue, icon: Icons.storage)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Public Assets', value: str(d['public_assets'], '0'), color: _kAmber, icon: Icons.public)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Critical Findings', value: str(d['critical_findings'], '0'), color: _kRed, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'IAM Risks', value: str(d['iam_risks'], '0'), color: _kPurple, icon: Icons.key)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Active Threats', value: str(d['active_threats'], '0'), color: _kRed, icon: Icons.bolt)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Compliance', value: '${str(d['compliance_score'], '0')}%', color: _kGreen, icon: Icons.verified_user)),
      ]),
      const SizedBox(height: 16),
      Row(children: [
        Expanded(child: SectionTitle('Connected Accounts')),
        TextButton(onPressed: _addAccount, child: const Text('Connect', style: TextStyle(fontSize: 12))),
      ]),
      const SizedBox(height: 8),
      if (_accounts.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No cloud accounts connected', style: TextStyle(color: Colors.grey)))
      else ..._accounts.map((a) {
        final m = a as Map<String,dynamic>;
        return _tile(icon: Icons.cloud_queue, title: str(m['name']),
          subtitle: '${str(m['provider']).toUpperCase()} · ${str(m['region'])} · ${str(m['asset_count'],'0')} assets',
          trailing: str(m['status']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Inventory by Provider'),
      const SizedBox(height: 8),
      ...((d['inventory'] as List?) ?? []).map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.cloud, title: str(m['provider']).toUpperCase(), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Recent Threats'),
      const SizedBox(height: 8),
      ...((d['recent_threats'] as List?) ?? []).map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(
          icon: Icons.bolt, iconColor: sevColor(str(m['severity'])),
          title: str(m['threat_type']).replaceAll('_', ' '),
          subtitle: '${str(m['provider'])} · ${str(m['resource_id'])} · ${str(m['source_ip'])}',
          trailing: timeAgo(m['created_at']),
        );
      }),
    ]));
  }

  Widget _inventoryTab() {
    if (_inventory.isEmpty) return const XEmptyState('No cloud assets discovered', icon: Icons.cloud_off_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _inventory.length,
      itemBuilder: (_, i) {
        final a = _inventory[i] as Map<String,dynamic>;
        final exposed = a['internet_exposed'] == true;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: exposed ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: exposed ? _kRed.withValues(alpha: .04) : null),
          child: Row(children: [
            Icon(Icons.dns_outlined, size: 18, color: exposed ? _kRed : Colors.grey),
            const SizedBox(width: 10),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(a['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              Text('${str(a['resource_type'])} · ${str(a['provider']).toUpperCase()} · ${str(a['region'])}',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ])),
            if (exposed) const Padding(padding: EdgeInsets.only(right: 6),
              child: _Pill(label: 'PUBLIC', color: _kRed)),
            Text('${str(a['risk_score'], '0')}', style: TextStyle(fontWeight: FontWeight.w800,
              color: (a['risk_score'] as int? ?? 0) > 70 ? _kRed : _kAmber)),
          ]),
        );
      },
    ));
  }

  Widget _cspmTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      if (_cspmSummary.isNotEmpty) ...[
        SectionTitle('By Category'),
        const SizedBox(height: 8),
        ..._cspmSummary.map((c) {
          final m = c as Map<String,dynamic>;
          return _tile(
            icon: Icons.category_outlined,
            title: str(m['category']).replaceAll('_', ' '),
            subtitle: '${str(m['critical'],'0')} critical · ${str(m['high'],'0')} high · ${str(m['medium'],'0')} medium',
            trailing: str(m['total']),
          );
        }),
        const SizedBox(height: 16),
      ],
      SectionTitle('Findings'),
      const SizedBox(height: 8),
      if (_findings.isEmpty) const XEmptyState('No open CSPM findings', icon: Icons.shield_outlined)
      else ..._findings.map((f) {
        final m = f as Map<String,dynamic>;
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
            Text('${str(m['provider']).toUpperCase()} · ${str(m['resource_type'])} · ${str(m['region'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['remediation']).isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(str(m['remediation']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            const SizedBox(height: 6),
            Align(alignment: Alignment.centerRight, child: TextButton(
              onPressed: () async {
                final ok = await widget.api.patchCloudFinding(m['id'] as int? ?? 0, 'resolved');
                if (context.mounted) xSnack(context, ok ? 'Marked resolved' : 'Failed', error: !ok);
                _load();
              },
              child: const Text('Mark Resolved', style: TextStyle(fontSize: 11)),
            )),
          ]),
        );
      }),
      if (_exposure != null) ...[
        const SizedBox(height: 16),
        SectionTitle('Exposure'),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(child: KpiCard(label: 'Public Buckets', value: str(_exposure!['public_buckets'],'0'), color: _kRed, icon: Icons.folder_open)),
          const SizedBox(width: 8),
          Expanded(child: KpiCard(label: 'Open DBs', value: str(_exposure!['open_databases'],'0'), color: _kRed, icon: Icons.storage)),
        ]),
        const SizedBox(height: 8),
        Row(children: [
          Expanded(child: KpiCard(label: 'Public APIs', value: str(_exposure!['public_apis'],'0'), color: _kAmber, icon: Icons.api)),
          const SizedBox(width: 8),
          Expanded(child: KpiCard(label: 'Weak SGs', value: str(_exposure!['weak_security_groups'],'0'), color: _kAmber, icon: Icons.security)),
        ]),
      ],
      if (_drift.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Drift Events'),
        const SizedBox(height: 8),
        ..._drift.map((d) {
          final m = d as Map<String,dynamic>;
          final ack = m['acknowledged'] == true;
          return Container(
            margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
              color: Theme.of(context).colorScheme.surfaceContainerLow),
            child: Row(children: [
              Icon(Icons.change_history, size: 16, color: sevColor(str(m['severity']))),
              const SizedBox(width: 10),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(str(m['change_type']).replaceAll('_', ' '), style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
                Text('${str(m['resource_id'])} · by ${str(m['changed_by'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ])),
              if (!ack) TextButton(
                onPressed: () async {
                  await widget.api.ackCloudDrift(m['id'] as int? ?? 0);
                  _load();
                },
                child: const Text('Ack', style: TextStyle(fontSize: 11)),
              ) else const _Pill(label: 'ACK\'D', color: _kGreen),
            ]),
          );
        }),
      ],
    ]));
  }

  Widget _ciemTab() {
    final risks = _ciemRisks ?? {};
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Dormant', value: str(risks['dormant_accounts'],'0'), color: Colors.grey, icon: Icons.person_off)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'No MFA', value: str(risks['no_mfa'],'0'), color: _kRed, icon: Icons.lock_open)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Old Keys', value: str(risks['old_access_keys'],'0'), color: _kAmber, icon: Icons.key_off)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Excessive Perms', value: str(risks['excessive_permissions'],'0'), color: _kOrange, icon: Icons.admin_panel_settings)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Identities'),
      const SizedBox(height: 8),
      if (_identities.isEmpty) const XEmptyState('No cloud identities discovered', icon: Icons.people_outline)
      else ..._identities.map((id) {
        final m = id as Map<String,dynamic>;
        final risk = str(m['risk_level']);
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              Text('${str(m['identity_type'])} · ${str(m['provider']).toUpperCase()}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
              Row(children: [
                if (m['is_dormant'] == true) const _Pill(label: 'DORMANT', color: Colors.grey),
                if (m['mfa_enabled'] != true) const Padding(padding: EdgeInsets.only(left: 4), child: _Pill(label: 'NO MFA', color: _kRed)),
              ]),
            ])),
            _Pill(label: risk.toUpperCase(), color: sevColor(risk)),
          ]),
        );
      }),
    ]));
  }

  Widget _detectionTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Active Threats'),
      const SizedBox(height: 8),
      if (_threats.isEmpty) const XEmptyState('No active cloud threats', icon: Icons.verified_user_outlined)
      else ..._threats.map((t0) {
        final t = t0 as Map<String,dynamic>;
        final sev = str(t['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(t['threat_type']).replaceAll('_', ' '),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(t['provider']).toUpperCase()} · ${str(t['resource_id'])} · ${str(t['source_ip'])} · ${str(t['source_user'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(t['mitre_technique']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('MITRE ${str(t['mitre_technique'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
            ],
            const SizedBox(height: 8),
            Row(children: [
              TextButton(onPressed: () => _respond('disable_iam_user', t), child: const Text('Disable Identity', style: TextStyle(fontSize: 11))),
              TextButton(onPressed: () => _respond('block_ip', t), child: const Text('Block IP', style: TextStyle(fontSize: 11))),
            ]),
          ]),
        );
      }),
      if (_vulns.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Vulnerabilities'),
        const SizedBox(height: 8),
        ..._vulns.map((v0) {
          final v = v0 as Map<String,dynamic>;
          final sev = str(v['severity']);
          return _tile(icon: Icons.bug_report_outlined, iconColor: sevColor(sev),
            title: str(v['title']),
            subtitle: '${str(v['provider']).toUpperCase()} · ${str(v['resource_type'])}',
            trailing: sev.toUpperCase());
        }),
      ],
    ]));
  }

  Future<void> _respond(String action, Map<String,dynamic> t) async {
    final res = await widget.api.cloudRespond({
      'action': action,
      'resource_id': str(t['resource_id']),
      'provider': str(t['provider']),
      'source_user': str(t['source_user']),
      'source_ip': str(t['source_ip']),
    });
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  Widget _complianceTab() {
    if (_compliance.isEmpty) return const XEmptyState('No compliance frameworks tracked', icon: Icons.checklist_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _compliance.length,
      itemBuilder: (_, i) {
        final f = _compliance[i] as Map<String,dynamic>;
        final score = (f['score'] as num?)?.toDouble() ?? 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 10), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(f['framework']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text('${score.toStringAsFixed(0)}%', style: TextStyle(fontWeight: FontWeight.w800,
                color: score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed)),
            ]),
            const SizedBox(height: 6),
            ClipRRect(borderRadius: BorderRadius.circular(4), child: LinearProgressIndicator(
              value: score / 100, minHeight: 6,
              backgroundColor: _kRed.withValues(alpha: .15),
              valueColor: AlwaysStoppedAnimation(score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed))),
            const SizedBox(height: 4),
            Text('${str(f['passed'],'0')} passed / ${str(f['failed'],'0')} failed of ${str(f['total'],'0')}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ]),
        );
      },
    ));
  }

  Widget _attackPathsTab() {
    final nodes = (_attackPaths?['nodes'] as List?) ?? [];
    final edges = (_attackPaths?['edges'] as List?) ?? [];
    if (nodes.isEmpty) return const XEmptyState('No attack paths found', icon: Icons.route_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Nodes', value: '${nodes.length}', color: _kBlue, icon: Icons.device_hub)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Edges', value: '${edges.length}', color: _kRed, icon: Icons.call_split)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Path Steps'),
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
    ]));
  }

  Widget _intelTab() {
    final ti = _threatIntel ?? {};
    final topIPs = (ti['top_source_ips'] as List?) ?? [];
    final byType = (ti['by_threat_type'] as List?) ?? [];
    final byProvider = (ti['by_provider'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Top Source IPs'),
      const SizedBox(height: 8),
      if (topIPs.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 12),
        child: Text('No repeat offenders observed', style: TextStyle(color: Colors.grey)))
      else ...topIPs.map((ip) {
        final m = ip as Map<String,dynamic>;
        return _tile(icon: Icons.public, title: str(m['ip']), subtitle: str(m['threat_types']), trailing: '${str(m['hits'])} hits');
      }),
      const SizedBox(height: 16),
      SectionTitle('By Threat Type'),
      const SizedBox(height: 8),
      ...byType.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.category, title: str(m['threat_type']).replaceAll('_', ' '),
          subtitle: '${str(m['critical'],'0')} critical', trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('By Provider'),
      const SizedBox(height: 8),
      ...byProvider.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.cloud, title: str(m['provider']).toUpperCase(), trailing: str(m['count']));
      }),
    ]));
  }

  Widget _analyticsTab() {
    final a = _analytics ?? {};
    final topExposed   = (a['top_exposed'] as List?) ?? [];
    final topMisconfig = (a['top_misconfigs'] as List?) ?? [];
    final byRegion      = (a['by_region'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Top Exposed Resources'),
      const SizedBox(height: 8),
      ...topExposed.map((e) {
        final m = e as Map<String,dynamic>;
        return _tile(icon: Icons.warning_amber, iconColor: _kRed, title: str(m['name']),
          subtitle: '${str(m['resource_type'])} · ${str(m['provider']).toUpperCase()}', trailing: str(m['risk_score']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Top Misconfigurations'),
      const SizedBox(height: 8),
      ...topMisconfig.map((m0) {
        final m = m0 as Map<String,dynamic>;
        return _tile(icon: Icons.report_problem_outlined, title: str(m['category']).replaceAll('_', ' '),
          subtitle: '${str(m['critical'],'0')} critical', trailing: str(m['total']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Risk by Region'),
      const SizedBox(height: 8),
      ...byRegion.map((r) {
        final m = r as Map<String,dynamic>;
        return _tile(icon: Icons.location_on_outlined, title: str(m['region']),
          subtitle: '${str(m['assets'])} assets', trailing: 'avg risk ${str(m['avg_risk'])}');
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
