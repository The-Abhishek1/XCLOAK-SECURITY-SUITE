import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Supply Chain — real SCA/SBOM/CI-CD-security dashboard backed by
// /api/supply-chain/* (api/supply_chain_enterprise.go). Was previously
// showing nothing at all: the shared ItdrScreen filtered
// /api/itdr/findings?type=supply_chain, a value that column never holds.
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

class SupplyChainScreen extends StatefulWidget {
  final DashboardApi api;
  const SupplyChainScreen({super.key, required this.api});
  @override State<SupplyChainScreen> createState() => _SupplyChainState();
}

class _SupplyChainState extends State<SupplyChainScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 10, vsync: this);

  Map<String,dynamic>? _dashboard;
  List _repos = [], _deps = [], _sboms = [], _pipelines = [], _artifacts = [],
       _timeline = [], _policies = [];
  Map<String,dynamic>? _vulns, _secrets, _codeIntegrity, _thirdParty,
      _provenance, _threatIntel, _analytics, _compliance;
  bool _loading = true;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.supplyChainDashboard(),
      widget.api.supplyChainRepositories(),
      widget.api.supplyChainDependencies(),
      widget.api.supplyChainVulnerabilities(),
      widget.api.supplyChainSBOMs(),
      widget.api.supplyChainPipelines(),
      widget.api.supplyChainSecrets(),
      widget.api.supplyChainCodeIntegrity(),
      widget.api.supplyChainArtifacts(),
      widget.api.supplyChainThirdParty(),
      widget.api.supplyChainProvenance(),
      widget.api.supplyChainThreatIntel(),
      widget.api.supplyChainTimeline(),
      widget.api.supplyChainAnalytics(),
      widget.api.supplyChainCompliance(),
      widget.api.supplyChainPolicies(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard      = r[0]  as Map<String,dynamic>?;
      _repos          = r[1]  as List;
      _deps           = r[2]  as List;
      _vulns          = r[3]  as Map<String,dynamic>?;
      _sboms          = r[4]  as List;
      _pipelines      = r[5]  as List;
      _secrets        = r[6]  as Map<String,dynamic>?;
      _codeIntegrity  = r[7]  as Map<String,dynamic>?;
      _artifacts      = r[8]  as List;
      _thirdParty     = r[9]  as Map<String,dynamic>?;
      _provenance     = r[10] as Map<String,dynamic>?;
      _threatIntel    = r[11] as Map<String,dynamic>?;
      _timeline       = r[12] as List;
      _analytics      = r[13] as Map<String,dynamic>?;
      _compliance     = r[14] as Map<String,dynamic>?;
      _policies       = r[15] as List;
      _loading        = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Repositories'), Tab(text: 'Dependencies'),
        Tab(text: 'Vulnerabilities'), Tab(text: 'Build & Artifacts'), Tab(text: 'Pipelines'),
        Tab(text: 'Threat Intel'), Tab(text: 'Compliance'), Tab(text: 'Analytics'),
        Tab(text: 'Policies'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _repositoriesTab(), _dependenciesTab(), _vulnerabilitiesTab(),
        _buildArtifactsTab(), _pipelinesTab(), _threatIntelTab(), _complianceTab(),
        _analyticsTab(), _policiesTab(),
      ])),
    ]);
  }

  void _addPolicy() {
    final nameCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    String ruleType = 'dependency';
    String action   = 'block';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Supply Chain Policy'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Rule Type', ruleType, ['dependency','pipeline','secret','artifact'], (v) => ss(() => ruleType = v!)),
          const SizedBox(height: 10),
          xDropdown('Action', action, ['block','warn','notify'], (v) => ss(() => action = v!)),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description', maxLines: 2),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createSupplyChainPolicy({
                'name': nameCtrl.text.trim(), 'rule_type': ruleType,
                'action': action, 'description': descCtrl.text.trim(),
              });
              if (context.mounted) xSnack(context, ok ? 'Policy created' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  Future<void> _respond(String action, String target, {String reason = ''}) async {
    final res = await widget.api.supplyChainRespond({'action': action, 'target': target, 'reason': reason});
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], 'Done'), error: err != null);
    _load();
  }

  Widget _overviewTab() {
    final d = _dashboard ?? {};
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Repositories', value: str(d['repositories'], '0'), color: _kBlue, icon: Icons.source)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Dependencies', value: str(d['dependencies'], '0'), color: _kPurple, icon: Icons.inventory_2)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Critical CVEs', value: str(d['critical_cves'], '0'), color: _kRed, icon: Icons.bug_report)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'High-Risk Pkgs', value: str(d['high_risk_packages'], '0'), color: _kOrange, icon: Icons.warning_amber)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'SBOMs', value: str(d['sboms'], '0'), color: _kGreen, icon: Icons.description)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Build Pipelines', value: str(d['build_pipelines'], '0'), color: _kBlue, icon: Icons.settings_suggest)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Signed Artifacts', value: '${str(d['signed_artifacts'],'0')}/${str(d['total_artifacts'],'0')}', color: _kGreen, icon: Icons.verified)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Open Secrets', value: str(d['secret_findings'], '0'), color: _kRed, icon: Icons.key_off)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Risk Score', value: str(d['risk_score'], '0'), color: _kAmber, icon: Icons.speed)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Riskiest Repositories'),
      const SizedBox(height: 8),
      if (_repos.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No repositories discovered', style: TextStyle(color: Colors.grey)))
      else ..._repos.take(5).map((r) {
        final m = r as Map<String,dynamic>;
        return _tile(icon: Icons.source, title: str(m['name']),
          subtitle: '${str(m['owner'])} · ${str(m['platform'])} · ${str(m['dep_count'],'0')} deps',
          trailing: 'risk ${str(m['risk_score'],'0')}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Recent Activity'),
      const SizedBox(height: 8),
      if (_timeline.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No recent supply chain events', style: TextStyle(color: Colors.grey)))
      else ..._timeline.take(8).map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(
          icon: Icons.history, iconColor: sevColor(str(m['severity'])),
          title: str(m['detail']),
          subtitle: str(m['event_type']).replaceAll('_', ' '),
          trailing: timeAgo(m['created_at']),
        );
      }),
    ]));
  }

  Widget _repositoriesTab() {
    if (_repos.isEmpty) return const XEmptyState('No repositories discovered', icon: Icons.source_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _repos.length,
      itemBuilder: (_, i) {
        final r = _repos[i] as Map<String,dynamic>;
        final risky = (r['risk_score'] as int? ?? 0) > 70;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: risky ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: risky ? _kRed.withValues(alpha: .04) : null),
          child: Row(children: [
            Icon(Icons.source_outlined, size: 18, color: risky ? _kRed : Colors.grey),
            const SizedBox(width: 10),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(r['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700)),
              Text('${str(r['owner'])} · ${str(r['platform'])} · ${str(r['language'])} · ${str(r['default_branch'])} · ${str(r['contributor_count'],'0')} contributors',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ])),
            if (r['is_private'] == true) const Padding(padding: EdgeInsets.only(right: 6),
              child: _Pill(label: 'PRIVATE', color: _kBlue)),
            Text('${str(r['risk_score'], '0')}', style: TextStyle(fontWeight: FontWeight.w800,
              color: risky ? _kRed : _kAmber)),
          ]),
        );
      },
    ));
  }

  Widget _dependenciesTab() {
    final packages = (_thirdParty?['packages'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Dependencies'),
      const SizedBox(height: 8),
      if (_deps.isEmpty) const XEmptyState('No dependencies discovered', icon: Icons.inventory_2_outlined)
      else ..._deps.map((d0) {
        final m = d0 as Map<String,dynamic>;
        final sev = (m['cve_count'] as int? ?? 0) > 0 ? 'high' : 'low';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['package_name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              if ((m['cve_count'] as int? ?? 0) > 0) _Pill(label: '${m['cve_count']} CVE', color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['ecosystem']).toUpperCase()} · v${str(m['version'])} → ${str(m['latest_version'])} · ${str(m['license'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 6),
            Row(children: [
              if (m['is_direct'] == true) const _Pill(label: 'DIRECT', color: _kBlue)
              else const _Pill(label: 'TRANSITIVE', color: Colors.grey),
              if (m['is_outdated'] == true) const Padding(padding: EdgeInsets.only(left: 4),
                child: _Pill(label: 'OUTDATED', color: _kAmber)),
              const Spacer(),
              Text('risk ${str(m['risk_score'],'0')}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ]),
          ]),
        );
      }),
      if (packages.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Third-Party Trust'),
        const SizedBox(height: 8),
        ...packages.map((p) {
          final m = p as Map<String,dynamic>;
          final trust = m['trust_score'] as int? ?? 0;
          return _tile(
            icon: Icons.shield_outlined, iconColor: trust < 50 ? _kRed : trust < 80 ? _kAmber : _kGreen,
            title: str(m['name']),
            subtitle: '${str(m['ecosystem']).toUpperCase()} · v${str(m['version'])} · ${str(m['license'])}',
            trailing: 'trust $trust',
          );
        }),
      ],
    ]));
  }

  Widget _vulnerabilitiesTab() {
    final v = _vulns ?? {};
    final list = (v['vulns'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Critical', value: str(v['critical'],'0'), color: _kRed, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'High', value: str(v['high'],'0'), color: _kOrange, icon: Icons.error_outline)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Known Exploited', value: str(v['kev'],'0'), color: _kRed, icon: Icons.bolt)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Actively Exploited', value: str(v['exploited'],'0'), color: _kPurple, icon: Icons.dangerous)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('CVEs'),
      const SizedBox(height: 8),
      if (list.isEmpty) const XEmptyState('No known vulnerabilities', icon: Icons.verified_user_outlined)
      else ...list.map((v0) {
        final m = v0 as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: sevColor(sev).withValues(alpha: .3)), color: sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['cve_id']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              if (m['is_kev'] == true) const Padding(padding: EdgeInsets.only(right: 4), child: _Pill(label: 'KEV', color: _kRed)),
              _Pill(label: sev.toUpperCase(), color: sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('CVSS ${str(m['cvss'])} · EPSS ${str(m['epss'])} · fix in ${str(m['fix_version'], 'none')}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['description']).isNotEmpty) ...[
              const SizedBox(height: 6),
              Text(str(m['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            if (str(m['affected_projects']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('Affects: ${str(m['affected_projects'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
            ],
            if (m['has_exploit'] == true || m['is_kev'] == true) ...[
              const SizedBox(height: 8),
              Align(alignment: Alignment.centerRight, child: TextButton(
                onPressed: () => _respond('create_incident', str(m['cve_id']), reason: str(m['description'])),
                child: const Text('Escalate to Incident', style: TextStyle(fontSize: 11)),
              )),
            ],
          ]),
        );
      }),
    ]));
  }

  Widget _buildArtifactsTab() {
    final prov = _provenance ?? {};
    final builds = (prov['builds'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'SLSA Level', value: str(prov['slsa_level'],'0'), color: _kPurple, icon: Icons.grade)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Provenance Rate', value: '${str(prov['provenance_rate'],'0')}%', color: _kGreen, icon: Icons.fact_check)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('SBOMs'),
      const SizedBox(height: 8),
      if (_sboms.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No SBOMs generated', style: TextStyle(color: Colors.grey)))
      else ..._sboms.map((s) {
        final m = s as Map<String,dynamic>;
        return _tile(
          icon: Icons.description_outlined, iconColor: m['has_vulnerabilities'] == true ? _kRed : _kGreen,
          title: str(m['artifact_name']),
          subtitle: '${str(m['format']).toUpperCase()} · ${str(m['component_count'],'0')} components · ${str(m['license_count'],'0')} licenses',
          trailing: timeAgo(m['generated_at']),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Artifacts'),
      const SizedBox(height: 8),
      if (_artifacts.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No build artifacts tracked', style: TextStyle(color: Colors.grey)))
      else ..._artifacts.map((a) {
        final m = a as Map<String,dynamic>;
        final risky = (m['risk_score'] as int? ?? 0) > 70 || m['is_signed'] != true;
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text('${str(m['name'])}:${str(m['version'])}', style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600))),
              if (m['is_signed'] == true) const _Pill(label: 'SIGNED', color: _kGreen)
              else const _Pill(label: 'UNSIGNED', color: _kRed),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['artifact_type'])} · ${m['has_sbom'] == true ? 'has SBOM' : 'no SBOM'} · ${m['provenance_available'] == true ? 'has provenance' : 'no provenance'}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (risky) ...[
              const SizedBox(height: 6),
              Align(alignment: Alignment.centerRight, child: TextButton(
                onPressed: () => _respond('quarantine_artifact', str(m['name'])),
                child: const Text('Quarantine', style: TextStyle(fontSize: 11)),
              )),
            ],
          ]),
        );
      }),
      if (builds.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Recent Builds'),
        const SizedBox(height: 8),
        ...builds.map((b) {
          final m = b as Map<String,dynamic>;
          return _tile(icon: Icons.build_outlined, iconColor: m['signed'] == true ? _kGreen : _kAmber,
            title: str(m['artifact']), subtitle: str(m['artifact_type']), trailing: timeAgo(m['build_time']));
        }),
      ],
    ]));
  }

  Widget _pipelinesTab() {
    final s = _secrets ?? {};
    final secretsList = (s['secrets'] as List?) ?? [];
    final ci = _codeIntegrity ?? {};
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Build Pipelines'),
      const SizedBox(height: 8),
      if (_pipelines.isEmpty) const XEmptyState('No build pipelines discovered', icon: Icons.settings_suggest_outlined)
      else ..._pipelines.map((p) {
        final m = p as Map<String,dynamic>;
        final blocked = str(m['status']) == 'blocked' || str(m['status']) == 'disabled';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              StatusChip(str(m['status'])),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['platform'])} · last run ${timeAgo(m['last_run'])}', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 6),
            Row(children: [
              if (m['has_secrets'] == true) const Padding(padding: EdgeInsets.only(right: 4), child: _Pill(label: 'HAS SECRETS', color: _kRed)),
              if (m['has_untrusted_actions'] == true) const Padding(padding: EdgeInsets.only(right: 4), child: _Pill(label: 'UNTRUSTED ACTIONS', color: _kOrange)),
              if (m['has_pinned_versions'] != true) const _Pill(label: 'UNPINNED', color: _kAmber),
            ]),
            if (!blocked && ((m['has_secrets'] == true) || (m['has_untrusted_actions'] == true))) ...[
              const SizedBox(height: 8),
              Row(children: [
                TextButton(onPressed: () => _respond('block_build', str(m['name'])), child: const Text('Block Build', style: TextStyle(fontSize: 11))),
                TextButton(onPressed: () => _respond('disable_pipeline', str(m['name'])), child: const Text('Disable Pipeline', style: TextStyle(fontSize: 11))),
              ]),
            ],
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Secret Scanning'),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Open', value: str(s['open'],'0'), color: _kRed, icon: Icons.key_off)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Total', value: str(s['total'],'0'), color: _kBlue, icon: Icons.vpn_key)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'AWS Keys', value: str(s['aws_keys'],'0'), color: _kOrange, icon: Icons.cloud_off)),
      ]),
      const SizedBox(height: 8),
      if (secretsList.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No secrets detected', style: TextStyle(color: Colors.grey)))
      else ...secretsList.map((sc) {
        final m = sc as Map<String,dynamic>;
        return _tile(icon: Icons.key_off_outlined, iconColor: sevColor(str(m['severity'])),
          title: str(m['secret_type']),
          subtitle: '${str(m['file_path'])} · ${str(m['commit_hash'])}',
          trailing: str(m['status']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Code Integrity'),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Signed Commits', value: '${str(ci['signed_commits_rate'],'0')}%', color: _kGreen, icon: Icons.verified_user)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Protected Branches', value: str(ci['protected_branches'],'0'), color: _kBlue, icon: Icons.lock_outline)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Force Pushes', value: str(ci['force_push_incidents'],'0'), color: _kAmber, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Unsigned Repos', value: str(ci['unsigned_commit_repos'],'0'), color: _kRed, icon: Icons.no_encryption)),
      ]),
    ]));
  }

  Widget _threatIntelTab() {
    final ti = _threatIntel ?? {};
    final malicious = (ti['malicious_packages'] as List?) ?? [];
    final iocs       = (ti['ioc_matches'] as List?) ?? [];
    final cves       = (ti['exploited_cves'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      if (iocs.isNotEmpty) ...[
        SectionTitle('Matches In Your Inventory'),
        const SizedBox(height: 8),
        ...iocs.map((i) {
          final m = i as Map<String,dynamic>;
          return _tile(icon: Icons.report_gmailerrorred, iconColor: _kRed, title: str(m['value']),
            subtitle: str(m['category']).replaceAll('_', ' '), trailing: '${str(m['hits'])} hits');
        }),
        const SizedBox(height: 16),
      ],
      SectionTitle('Known Malicious Packages'),
      const SizedBox(height: 8),
      ...malicious.map((m0) {
        final m = m0 as Map<String,dynamic>;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text('${str(m['name'])} (${str(m['ecosystem'])})', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text(str(m['discovered']), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            ]),
            const SizedBox(height: 4),
            Text(str(m['threat']), style: const TextStyle(fontSize: 11.5)),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Exploited CVEs'),
      const SizedBox(height: 8),
      ...cves.map((c) {
        final m = c as Map<String,dynamic>;
        return _tile(icon: Icons.bolt, iconColor: m['kev'] == true ? _kRed : _kAmber,
          title: str(m['cve']), subtitle: str(m['package']), trailing: 'CVSS ${str(m['cvss'])}');
      }),
    ]));
  }

  Widget _complianceTab() {
    final c = _compliance ?? {};
    final frameworks = (c['frameworks'] as List?) ?? [];
    final failed = (c['failed_controls'] as List?) ?? [];
    if (frameworks.isEmpty && failed.isEmpty) return const XEmptyState('No compliance frameworks tracked', icon: Icons.checklist_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Overall Score', value: '${str(c['overall_score'],'0')}%', color: _kGreen, icon: Icons.verified)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Frameworks'),
      const SizedBox(height: 8),
      ...frameworks.map((f) {
        final m = f as Map<String,dynamic>;
        final score = (m['score'] as num?)?.toDouble() ?? 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 10), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Text('${score.toStringAsFixed(0)}%', style: TextStyle(fontWeight: FontWeight.w800,
                color: score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed)),
            ]),
            const SizedBox(height: 6),
            ClipRRect(borderRadius: BorderRadius.circular(4), child: LinearProgressIndicator(
              value: score / 100, minHeight: 6,
              backgroundColor: _kRed.withValues(alpha: .15),
              valueColor: AlwaysStoppedAnimation(score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed))),
            const SizedBox(height: 4),
            Text('${str(m['passed'],'0')} passed / ${str(m['failed'],'0')} failed of ${str(m['total'],'0')}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
          ]),
        );
      }),
      if (failed.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Failed Controls'),
        const SizedBox(height: 8),
        ...failed.map((f) {
          final m = f as Map<String,dynamic>;
          return _tile(icon: Icons.error_outline, iconColor: sevColor(str(m['severity'])),
            title: '${str(m['control'])} — ${str(m['title'])}', subtitle: str(m['framework']),
            trailing: str(m['severity']).toUpperCase());
        }),
      ],
    ]));
  }

  Widget _analyticsTab() {
    final a = _analytics ?? {};
    final trend       = (a['compliance_trend'] as List?) ?? [];
    final topVulnProj = (a['most_vulnerable_projects'] as List?) ?? [];
    final topDeps     = (a['most_used_dependencies'] as List?) ?? [];
    final secretTypes = (a['secret_findings_by_type'] as List?) ?? [];
    final failures    = (a['build_failures'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      if (trend.isNotEmpty) ...[
        SectionTitle('CVE Trend (14 days)'),
        const SizedBox(height: 8),
        _tile(icon: Icons.trending_up, title: '${str((trend.first as Map)['count'])} → ${str((trend.last as Map)['count'])}',
          subtitle: '${str((trend.first as Map)['date'])} through ${str((trend.last as Map)['date'])}'),
        const SizedBox(height: 16),
      ],
      SectionTitle('Most Vulnerable Projects'),
      const SizedBox(height: 8),
      if (topVulnProj.isEmpty) const Padding(padding: EdgeInsets.symmetric(vertical: 8),
        child: Text('No repository-linked vulnerabilities found', style: TextStyle(color: Colors.grey)))
      else ...topVulnProj.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.bug_report_outlined, iconColor: _kRed, title: str(m['name']),
          subtitle: '${str(m['critical'],'0')} critical of ${str(m['cve_count'],'0')} CVEs', trailing: 'risk ${str(m['risk'],'0')}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Most Used Dependencies'),
      const SizedBox(height: 8),
      ...topDeps.map((d) {
        final m = d as Map<String,dynamic>;
        return _tile(icon: Icons.widgets_outlined, iconColor: m['has_vuln'] == true ? _kRed : _kGreen,
          title: str(m['package']), subtitle: str(m['ecosystem']).toUpperCase(), trailing: 'used by ${str(m['used_by'])}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Secret Findings By Type'),
      const SizedBox(height: 8),
      ...secretTypes.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.key_off_outlined, title: str(m['type']), trailing: str(m['count']));
      }),
      if (failures.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Build Failures'),
        const SizedBox(height: 8),
        ...failures.map((f) {
          final m = f as Map<String,dynamic>;
          return _tile(icon: Icons.error_outline, iconColor: _kRed, title: str(m['pipeline']), trailing: timeAgo(m['last_failure']));
        }),
      ],
    ]));
  }

  Widget _policiesTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: SectionTitle('Policies')),
        TextButton(onPressed: _addPolicy, child: const Text('New Policy', style: TextStyle(fontSize: 12))),
      ]),
      const SizedBox(height: 8),
      if (_policies.isEmpty) const XEmptyState('No supply chain policies configured', icon: Icons.policy_outlined)
      else ..._policies.map((p) {
        final m = p as Map<String,dynamic>;
        final enabled = m['is_enabled'] == true;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              Switch(value: enabled, onChanged: (v) async {
                await widget.api.patchSupplyChainPolicy(m['id'] as int? ?? 0, {'is_enabled': v});
                _load();
              }),
            ]),
            Text('${str(m['rule_type']).replaceAll('_',' ')} · action: ${str(m['action'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['description']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(m['description']), style: const TextStyle(fontSize: 11.5)),
            ],
            const SizedBox(height: 6),
            Align(alignment: Alignment.centerRight, child: TextButton(
              onPressed: () async {
                final ok = await xConfirm(context, 'Delete Policy', 'Remove "${str(m['name'])}"? This cannot be undone.');
                if (!ok) return;
                await widget.api.deleteSupplyChainPolicy(m['id'] as int? ?? 0);
                if (context.mounted) xSnack(context, 'Policy deleted');
                _load();
              },
              child: const Text('Delete', style: TextStyle(fontSize: 11, color: _kRed)),
            )),
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
