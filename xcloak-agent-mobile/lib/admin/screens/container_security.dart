import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Container Security — real K8s/container posture, runtime detection, RBAC,
// supply-chain and compliance dashboard backed by /api/containers/*
// (api/container_security_enterprise.go). Was previously showing nothing at
// all: the shared ItdrScreen filtered /api/itdr/findings by type='container',
// a value that column never actually holds.
// ─────────────────────────────────────────────────────────────────────────────

const _kRed    = Color(0xFFEF4444);
const _kOrange = Color(0xFFF97316);
const _kAmber  = Color(0xFFF59E0B);
const _kBlue   = Color(0xFF3B82F6);
const _kGreen  = Color(0xFF22C55E);
const _kPurple = Color(0xFF8B5CF6);

Color _sevColor(String sev) => switch (sev.toLowerCase()) {
  'critical' => _kRed,
  'high'     => _kOrange,
  'medium'   => _kAmber,
  _          => _kBlue,
};

class ContainerSecurityScreen extends StatefulWidget {
  final DashboardApi api;
  const ContainerSecurityScreen({super.key, required this.api});
  @override State<ContainerSecurityScreen> createState() => _ContainerSecurityState();
}

class _ContainerSecurityState extends State<ContainerSecurityScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 9, vsync: this);

  Map<String,dynamic>? _dashboard, _supplyChain, _rbac, _secrets, _compliance,
      _attackPaths, _threatIntel, _analytics;
  List _clusters = [], _nodes = [], _namespaces = [], _pods = [], _images = [],
      _vulns = [], _runtimeAlerts = [], _networkPolicies = [], _admission = [],
      _timeline = [];
  bool _loading = true;

  @override
  void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await Future.wait([
      widget.api.containerDashboard(),
      widget.api.containerClusters(),
      widget.api.containerNodes(),
      widget.api.containerNamespaces(),
      widget.api.containerPods(),
      widget.api.containerImages(),
      widget.api.containerSupplyChain(),
      widget.api.containerVulnerabilities(),
      widget.api.containerRuntimeAlerts(),
      widget.api.containerRBAC(),
      widget.api.containerSecrets(),
      widget.api.containerNetworkPolicies(),
      widget.api.containerAdmission(),
      widget.api.containerCompliance(),
      widget.api.containerAttackPaths(),
      widget.api.containerThreatIntel(),
      widget.api.containerAnalytics(),
      widget.api.containerTimeline(),
    ]);
    if (!mounted) return;
    setState(() {
      _dashboard       = r[0]  as Map<String,dynamic>?;
      _clusters        = r[1]  as List;
      _nodes           = r[2]  as List;
      _namespaces      = r[3]  as List;
      _pods            = r[4]  as List;
      _images          = r[5]  as List;
      _supplyChain     = r[6]  as Map<String,dynamic>?;
      _vulns           = r[7]  as List;
      _runtimeAlerts   = r[8]  as List;
      _rbac            = r[9]  as Map<String,dynamic>?;
      _secrets         = r[10] as Map<String,dynamic>?;
      _networkPolicies = r[11] as List;
      _admission       = r[12] as List;
      _compliance      = r[13] as Map<String,dynamic>?;
      _attackPaths     = r[14] as Map<String,dynamic>?;
      _threatIntel     = r[15] as Map<String,dynamic>?;
      _analytics       = r[16] as Map<String,dynamic>?;
      _timeline        = r[17] as List;
      _loading         = false;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Overview'), Tab(text: 'Clusters'), Tab(text: 'Workloads'),
        Tab(text: 'Images'), Tab(text: 'Runtime'), Tab(text: 'RBAC & Secrets'),
        Tab(text: 'Network'), Tab(text: 'Compliance'), Tab(text: 'Intel & Paths'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _overviewTab(), _clustersTab(), _workloadsTab(), _imagesTab(),
        _runtimeTab(), _rbacTab(), _networkTab(), _complianceTab(), _intelTab(),
      ])),
    ]);
  }

  Future<void> _respond(String action, Map<String,dynamic> body, {String? successMsg}) async {
    final res = await widget.api.containerRespond({'action': action, ...body});
    if (!mounted) return;
    final err = res?['error'];
    xSnack(context, err != null ? str(err) : str(res?['message'], successMsg ?? 'Done'), error: err != null);
    _load();
  }

  Widget _overviewTab() {
    final d = _dashboard ?? {};
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Clusters', value: str(d['clusters'], '0'), color: _kBlue, icon: Icons.hub_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Nodes', value: str(d['nodes'], '0'), color: _kBlue, icon: Icons.dns_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Pods', value: str(d['pods'], '0'), color: _kGreen, icon: Icons.widgets_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Namespaces', value: str(d['namespaces'], '0'), color: _kGreen, icon: Icons.folder_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Critical Findings', value: str(d['critical_findings'], '0'), color: _kRed, icon: Icons.warning_amber)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Vulnerable Images', value: str(d['vulnerable_images'], '0'), color: _kOrange, icon: Icons.bug_report_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Runtime Alerts', value: str(d['runtime_alerts'], '0'), color: _kRed, icon: Icons.bolt)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Compliance', value: '${str(d['compliance_score'], '0')}%', color: _kGreen, icon: Icons.verified_user)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Privileged Pods', value: str(d['privileged_pods'], '0'), color: _kAmber, icon: Icons.no_encryption_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'No Resource Limits', value: str(d['pods_no_limits'], '0'), color: _kAmber, icon: Icons.speed_outlined)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Recent Runtime Events'),
      const SizedBox(height: 8),
      if (_timeline.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No runtime events recorded', style: TextStyle(color: Colors.grey)))
      else ..._timeline.take(15).map((e) {
        final m = e as Map<String,dynamic>;
        return _tile(
          icon: Icons.bolt, iconColor: _sevColor(str(m['severity'])),
          title: str(m['event_type']).replaceAll('_', ' '),
          subtitle: '${str(m['namespace'])}/${str(m['pod_name'])} · ${str(m['description'])}',
          trailing: timeAgo(m['created_at']),
        );
      }),
    ]));
  }

  Widget _clustersTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Clusters'),
      const SizedBox(height: 8),
      if (_clusters.isEmpty)
        const XEmptyState('No Kubernetes clusters registered', icon: Icons.hub_outlined)
      else ..._clusters.map((c) {
        final m = c as Map<String,dynamic>;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: str(m['status']).toUpperCase(), color: str(m['status']) == 'healthy' ? _kGreen : _kAmber),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['provider']).toUpperCase()} · K8s ${str(m['k8s_version'])} · ${str(m['node_count'])} nodes · ${str(m['region'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 6),
            Row(children: [
              Text('Risk ${str(m['risk_score'],'0')}', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700,
                color: (m['risk_score'] as int? ?? 0) > 70 ? _kRed : _kAmber)),
              const SizedBox(width: 12),
              Text('Compliance ${str(m['compliance_score'],'0')}%', style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ]),
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Nodes'),
      const SizedBox(height: 8),
      if (_nodes.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No nodes discovered', style: TextStyle(color: Colors.grey)))
      else ..._nodes.map((n) {
        final m = n as Map<String,dynamic>;
        final cordoned = str(m['status']) == 'cordoned';
        return Container(
          margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            color: Theme.of(context).colorScheme.surfaceContainerLow),
          child: Row(children: [
            Icon(Icons.dns_outlined, size: 16, color: cordoned ? _kRed : Colors.grey),
            const SizedBox(width: 10),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(str(m['name']), style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600)),
              Text('${str(m['os'])} · ${str(m['runtime'])} · ${str(m['pod_count'])} pods · ${str(m['vuln_count'])} vulns',
                style: const TextStyle(fontSize: 11, color: Colors.grey)),
            ])),
            if (cordoned)
              const _Pill(label: 'CORDONED', color: _kRed)
            else TextButton(
              onPressed: () => _respond('quarantine_node', {'node_name': str(m['name'])}, successMsg: 'Node cordoned'),
              child: const Text('Quarantine', style: TextStyle(fontSize: 11)),
            ),
          ]),
        );
      }),
    ]));
  }

  Widget _workloadsTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Namespaces'),
      const SizedBox(height: 8),
      if (_namespaces.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No namespaces discovered', style: TextStyle(color: Colors.grey)))
      else ..._namespaces.map((n) {
        final m = n as Map<String,dynamic>;
        return _tile(icon: Icons.folder_outlined, title: str(m['namespace']),
          subtitle: '${str(m['pod_count'])} pods · ${str(m['privileged_pods'])} privileged',
          trailing: 'risk ${str(m['risk_score'])}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Pods'),
      const SizedBox(height: 8),
      if (_pods.isEmpty)
        const XEmptyState('No pods discovered', icon: Icons.widgets_outlined)
      else ..._pods.map((p) {
        final m = p as Map<String,dynamic>;
        final risky = m['is_privileged'] == true || m['run_as_root'] == true || m['host_network'] == true;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: risky ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: risky ? _kRed.withValues(alpha: .04) : null),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['name']), style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                maxLines: 1, overflow: TextOverflow.ellipsis)),
              Text('${str(m['risk_score'],'0')}', style: TextStyle(fontWeight: FontWeight.w800,
                color: (m['risk_score'] as int? ?? 0) > 70 ? _kRed : _kAmber)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['namespace'])} · ${str(m['image'])}', style: const TextStyle(fontSize: 11, color: Colors.grey),
              maxLines: 1, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 6),
            Wrap(spacing: 4, runSpacing: 4, children: [
              if (m['is_privileged'] == true) const _Pill(label: 'PRIVILEGED', color: _kRed),
              if (m['run_as_root'] == true) const _Pill(label: 'ROOT', color: _kRed),
              if (m['host_network'] == true) const _Pill(label: 'HOST NET', color: _kOrange),
              if (m['host_pid'] == true) const _Pill(label: 'HOST PID', color: _kOrange),
              if (m['has_resource_limits'] != true) const _Pill(label: 'NO LIMITS', color: _kAmber),
              _Pill(label: str(m['status']).toUpperCase(), color: str(m['status']) == 'running' ? _kGreen : Colors.grey),
            ]),
            if (str(m['status']) != 'terminated') ...[
              const SizedBox(height: 6),
              Row(children: [
                TextButton(
                  onPressed: () => _respond('kill_container', {'namespace': str(m['namespace']), 'pod_name': str(m['name'])}, successMsg: 'Container killed'),
                  child: const Text('Kill Container', style: TextStyle(fontSize: 11)),
                ),
                TextButton(
                  onPressed: () => _respond('delete_pod', {'namespace': str(m['namespace']), 'pod_name': str(m['name'])}, successMsg: 'Pod deleted'),
                  child: const Text('Delete Pod', style: TextStyle(fontSize: 11)),
                ),
              ]),
            ],
          ]),
        );
      }),
    ]));
  }

  Widget _imagesTab() {
    final sc = _supplyChain ?? {};
    final registries = (sc['trusted_registries'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Images', value: str(sc['total_images'], '0'), color: _kBlue, icon: Icons.layers_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Signed', value: '${str(sc['signature_rate'],'0')}%', color: _kGreen, icon: Icons.verified_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'SBOM Available', value: '${str(sc['sbom_rate'],'0')}%', color: _kGreen, icon: Icons.description_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Old Base Images', value: str(sc['old_base_images'], '0'), color: _kAmber, icon: Icons.history)),
      ]),
      if (registries.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Registries'),
        const SizedBox(height: 8),
        ...registries.map((r) {
          final m = r as Map<String,dynamic>;
          final trusted = m['trusted'] == true;
          return _tile(icon: trusted ? Icons.verified_user_outlined : Icons.help_outline,
            iconColor: trusted ? _kGreen : _kAmber,
            title: str(m['registry']),
            subtitle: trusted ? 'Trusted' : 'Untrusted',
            trailing: '${str(m['images'])} images');
        }),
      ],
      const SizedBox(height: 16),
      SectionTitle('Container Images'),
      const SizedBox(height: 8),
      if (_images.isEmpty)
        const XEmptyState('No images scanned', icon: Icons.layers_clear_outlined)
      else ..._images.map((im) {
        final m = im as Map<String,dynamic>;
        final blockable = m['malware_found'] == true || (m['cve_critical'] as int? ?? 0) > 0;
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: blockable ? _kRed.withValues(alpha: .3) : Theme.of(context).colorScheme.outlineVariant),
            color: blockable ? _kRed.withValues(alpha: .04) : null),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text('${str(m['image'])}:${str(m['tag'])}', style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700),
              maxLines: 1, overflow: TextOverflow.ellipsis),
            const SizedBox(height: 4),
            Text('${str(m['registry'])} · ${str(m['os'])} · ${str(m['size_mb'])}MB · ${str(m['age_days'])}d old',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            const SizedBox(height: 6),
            Wrap(spacing: 4, runSpacing: 4, children: [
              if ((m['cve_critical'] as int? ?? 0) > 0) _Pill(label: '${m['cve_critical']} CRITICAL', color: _kRed),
              if ((m['cve_high'] as int? ?? 0) > 0) _Pill(label: '${m['cve_high']} HIGH', color: _kOrange),
              if (m['malware_found'] == true) const _Pill(label: 'MALWARE', color: _kRed),
              if (m['has_secrets'] == true) const _Pill(label: 'SECRETS', color: _kAmber),
              _Pill(label: m['signature_valid'] == true ? 'SIGNED' : 'UNSIGNED', color: m['signature_valid'] == true ? _kGreen : Colors.grey),
              _Pill(label: m['sbom_available'] == true ? 'SBOM' : 'NO SBOM', color: m['sbom_available'] == true ? _kGreen : Colors.grey),
            ]),
            if (blockable) ...[
              const SizedBox(height: 6),
              Align(alignment: Alignment.centerRight, child: TextButton(
                onPressed: () => _respond('block_image', {'image': str(m['image'])}, successMsg: 'Image blocked'),
                child: const Text('Block Image', style: TextStyle(fontSize: 11)),
              )),
            ],
          ]),
        );
      }),
      if (_vulns.isNotEmpty) ...[
        const SizedBox(height: 16),
        SectionTitle('Most Vulnerable Images'),
        const SizedBox(height: 8),
        ..._vulns.map((v) {
          final m = v as Map<String,dynamic>;
          return _tile(icon: Icons.bug_report_outlined, iconColor: _kRed, title: str(m['image']),
            subtitle: '${str(m['cve_critical'],'0')} critical · ${str(m['cve_high'],'0')} high · ${str(m['cve_medium'],'0')} medium',
            trailing: 'risk ${str(m['risk_score'])}');
        }),
      ],
    ]));
  }

  Widget _runtimeTab() {
    if (_runtimeAlerts.isEmpty) return const XEmptyState('No runtime alerts', icon: Icons.verified_user_outlined);
    return RefreshIndicator(onRefresh: _load, child: ListView.builder(
      padding: const EdgeInsets.all(12), itemCount: _runtimeAlerts.length,
      itemBuilder: (_, i) {
        final a = _runtimeAlerts[i] as Map<String,dynamic>;
        final sev = str(a['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: _sevColor(sev).withValues(alpha: .3)), color: _sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(a['alert_type']).replaceAll('_', ' '),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: sev.toUpperCase(), color: _sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(a['namespace'])}/${str(a['pod_name'])} · ${str(a['container_name'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(a['description']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(a['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
            if (str(a['process']).isNotEmpty || str(a['command']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('${str(a['process'])} ${str(a['command'])}'.trim(), style: const TextStyle(fontSize: 10.5, fontFamily: 'monospace', color: Colors.grey),
                maxLines: 1, overflow: TextOverflow.ellipsis),
            ],
            if (str(a['mitre_technique']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text('MITRE ${str(a['mitre_technique'])}', style: const TextStyle(fontSize: 10.5, color: _kPurple)),
            ],
            const SizedBox(height: 8),
            Row(children: [
              Text(str(a['status']).toUpperCase(), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
              const Spacer(),
              if (str(a['pod_name']).isNotEmpty)
                TextButton(
                  onPressed: () => _respond('kill_container', {'namespace': str(a['namespace']), 'pod_name': str(a['pod_name'])}, successMsg: 'Container killed'),
                  child: const Text('Kill Container', style: TextStyle(fontSize: 11)),
                ),
            ]),
          ]),
        );
      },
    ));
  }

  Widget _rbacTab() {
    final r = _rbac ?? {};
    final findings = (r['findings'] as List?) ?? [];
    final s = _secrets ?? {};
    final providers = (s['providers'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Row(children: [
        Expanded(child: KpiCard(label: 'RBAC Findings', value: str(r['total'], '0'), color: _kRed, icon: Icons.admin_panel_settings)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Cluster Roles', value: str(r['cluster_roles'], '0'), color: _kBlue, icon: Icons.badge_outlined)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Excessive Perms', value: str(r['excessive'], '0'), color: _kOrange, icon: Icons.key_off)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Wildcard Perms', value: str(r['wildcard'], '0'), color: _kOrange, icon: Icons.star_outline)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('RBAC Findings'),
      const SizedBox(height: 8),
      if (findings.isEmpty) const XEmptyState('No RBAC findings', icon: Icons.shield_outlined)
      else ...findings.map((f) {
        final m = f as Map<String,dynamic>;
        final sev = str(m['severity']);
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: _sevColor(sev).withValues(alpha: .3)), color: _sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text('${str(m['kind'])} · ${str(m['name'])}', style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700),
                maxLines: 1, overflow: TextOverflow.ellipsis)),
              _Pill(label: sev.toUpperCase(), color: _sevColor(sev)),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['subject'])} · ${str(m['finding_type']).replaceAll('_', ' ')}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['description']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(m['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
          ]),
        );
      }),
      const SizedBox(height: 16),
      SectionTitle('Secrets Management'),
      const SizedBox(height: 8),
      KpiCard(label: 'Secret-Mounting Pods', value: str(s['total_secrets'], '0'), color: _kAmber, icon: Icons.password),
      const SizedBox(height: 8),
      ...providers.map((p) {
        final m = p as Map<String,dynamic>;
        final active = str(m['status']) == 'active';
        return _tile(icon: Icons.vpn_key_outlined, iconColor: active ? _kGreen : Colors.grey,
          title: str(m['name']), subtitle: str(m['status']).replaceAll('_', ' '), trailing: str(m['count']));
      }),
    ]));
  }

  Widget _networkTab() {
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Network Policies'),
      const SizedBox(height: 8),
      if (_networkPolicies.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 8),
          child: Text('No network policies defined', style: TextStyle(color: Colors.grey)))
      else ..._networkPolicies.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.rule_outlined, title: str(m['name']),
          subtitle: '${str(m['namespace'])} · ${str(m['policy_type'])} · ${str(m['direction'])} · ${str(m['peer'])}',
          trailing: str(m['status']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Admission Control'),
      const SizedBox(height: 8),
      if (_admission.isEmpty) const XEmptyState('No admission violations', icon: Icons.gpp_good_outlined)
      else ..._admission.map((v) {
        final m = v as Map<String,dynamic>;
        final sev = str(m['severity']);
        final denied = str(m['action']) == 'denied';
        return Container(
          margin: const EdgeInsets.only(bottom: 8), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
            border: Border.all(color: _sevColor(sev).withValues(alpha: .3)), color: _sevColor(sev).withValues(alpha: .05)),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(str(m['violation_type']).replaceAll('_', ' '),
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
              _Pill(label: str(m['action']).toUpperCase(), color: denied ? _kGreen : _kRed),
            ]),
            const SizedBox(height: 4),
            Text('${str(m['kind'])} ${str(m['workload'])} · ${str(m['namespace'])}',
              style: const TextStyle(fontSize: 11, color: Colors.grey)),
            if (str(m['description']).isNotEmpty) ...[
              const SizedBox(height: 4),
              Text(str(m['description']), style: const TextStyle(fontSize: 11.5), maxLines: 2, overflow: TextOverflow.ellipsis),
            ],
          ]),
        );
      }),
    ]));
  }

  Widget _complianceTab() {
    final c = _compliance ?? {};
    final score = (c['overall_score'] as num?)?.toDouble() ?? 0;
    final bySev = (c['by_severity'] as Map?) ?? {};
    final violations = (c['recent_violations'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(borderRadius: BorderRadius.circular(10),
          color: Theme.of(context).colorScheme.surfaceContainerLow),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            const Expanded(child: Text('Overall Compliance Score', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
            Text('${score.toStringAsFixed(0)}%', style: TextStyle(fontWeight: FontWeight.w800,
              color: score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed)),
          ]),
          const SizedBox(height: 8),
          ClipRRect(borderRadius: BorderRadius.circular(4), child: LinearProgressIndicator(
            value: score / 100, minHeight: 6,
            backgroundColor: _kRed.withValues(alpha: .15),
            valueColor: AlwaysStoppedAnimation(score >= 80 ? _kGreen : score >= 50 ? _kAmber : _kRed))),
        ]),
      ),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Violations', value: str(c['total_violations'], '0'), color: _kRed, icon: Icons.report_gmailerrorred)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Denied', value: str(c['denied'], '0'), color: _kGreen, icon: Icons.block)),
      ]),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Allowed', value: str(c['allowed'], '0'), color: _kAmber, icon: Icons.check_circle_outline)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Critical', value: str(bySev['critical'], '0'), color: _kRed, icon: Icons.priority_high)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('Recent Violations'),
      const SizedBox(height: 8),
      if (violations.isEmpty) const XEmptyState('No recent violations', icon: Icons.checklist_outlined)
      else ...violations.map((v) {
        final m = v as Map<String,dynamic>;
        final sev = str(m['severity']);
        return _tile(icon: Icons.report_problem_outlined, iconColor: _sevColor(sev),
          title: '${str(m['kind'])} ${str(m['workload'])}',
          subtitle: str(m['violation_type']).replaceAll('_', ' '),
          trailing: str(m['action']));
      }),
    ]));
  }

  Widget _intelTab() {
    final ti = _threatIntel ?? {};
    final malicious = (ti['malicious_images'] as List?) ?? [];
    final iocs = (ti['ioc_matches'] as List?) ?? [];
    final cves = (ti['recent_cves'] as List?) ?? [];
    final ap = _attackPaths ?? {};
    final riskPods = (ap['risk_pods'] as List?) ?? [];
    final riskRbac = (ap['risk_rbac'] as List?) ?? [];
    final a = _analytics ?? {};
    final trend = (a['runtime_alert_trend'] as List?) ?? [];
    final topImages = (a['top_vulnerable_images'] as List?) ?? [];
    final alertByType = (a['alert_by_type'] as List?) ?? [];
    final nsRisk = (a['namespace_risk'] as List?) ?? [];
    return RefreshIndicator(onRefresh: _load, child: ListView(padding: const EdgeInsets.all(12), children: [
      SectionTitle('Attack Paths — Risky Pods'),
      const SizedBox(height: 8),
      if (riskPods.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 4),
          child: Text('No privileged/root/host-network pods found', style: TextStyle(color: Colors.grey)))
      else ...riskPods.map((p) {
        final m = p as Map<String,dynamic>;
        return _tile(icon: Icons.route_outlined, iconColor: _kRed, title: str(m['name']),
          subtitle: '${str(m['namespace'])} · ${str(m['image'])}', trailing: 'risk ${str(m['risk_score'])}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Attack Paths — Risky RBAC'),
      const SizedBox(height: 8),
      if (riskRbac.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 4),
          child: Text('No excessive/wildcard RBAC bindings found', style: TextStyle(color: Colors.grey)))
      else ...riskRbac.map((rb) {
        final m = rb as Map<String,dynamic>;
        return _tile(icon: Icons.key_off, iconColor: _sevColor(str(m['severity'])),
          title: '${str(m['kind'])} ${str(m['name'])}', subtitle: str(m['subject']),
          trailing: str(m['finding_type']).replaceAll('_', ' '));
      }),
      const SizedBox(height: 16),
      SectionTitle('Malicious Images'),
      const SizedBox(height: 8),
      if (malicious.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 4),
          child: Text('No malware detected in scanned images', style: TextStyle(color: Colors.grey)))
      else ...malicious.map((m0) {
        final m = m0 as Map<String,dynamic>;
        return _tile(icon: Icons.dangerous_outlined, iconColor: _kRed, title: '${str(m['image'])}:${str(m['tag'])}', trailing: str(m['registry']));
      }),
      const SizedBox(height: 16),
      SectionTitle('IOC Matches'),
      const SizedBox(height: 8),
      if (iocs.isEmpty)
        const Padding(padding: EdgeInsets.symmetric(vertical: 4),
          child: Text('No IOC matches against known-bad image indicators', style: TextStyle(color: Colors.grey)))
      else ...iocs.map((ioc) {
        final m = ioc as Map<String,dynamic>;
        return _tile(icon: Icons.fingerprint, title: str(m['value']), subtitle: str(m['type']), trailing: '${str(m['hits'])} hits');
      }),
      const SizedBox(height: 16),
      SectionTitle('K8s Ecosystem Advisories'),
      const SizedBox(height: 8),
      ...cves.map((c) {
        final m = c as Map<String,dynamic>;
        return _tile(icon: Icons.info_outline, iconColor: _kPurple, title: str(m['cve']),
          subtitle: str(m['affected']), trailing: 'CVSS ${str(m['score'])}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Analytics'),
      const SizedBox(height: 8),
      Row(children: [
        Expanded(child: KpiCard(label: 'Total Pods', value: str(a['total_pods'], '0'), color: _kBlue, icon: Icons.widgets_outlined)),
        const SizedBox(width: 8),
        Expanded(child: KpiCard(label: 'Privileged Pods', value: str(a['privileged_pods'], '0'), color: _kRed, icon: Icons.no_encryption_outlined)),
      ]),
      const SizedBox(height: 16),
      SectionTitle('14-Day Runtime Alert Trend'),
      const SizedBox(height: 8),
      if (trend.isEmpty)
        const Text('No trend data', style: TextStyle(color: Colors.grey))
      else SizedBox(
        height: 60,
        child: Row(crossAxisAlignment: CrossAxisAlignment.end, children: trend.map((t) {
          final m = t as Map<String,dynamic>;
          final cnt = (m['count'] as num?)?.toInt() ?? 0;
          final maxCnt = trend.map((x) => ((x as Map)['count'] as num?)?.toInt() ?? 0).fold(1, (a, b) => a > b ? a : b);
          final h = cnt == 0 ? 2.0 : 6.0 + (cnt / maxCnt) * 44.0;
          return Expanded(child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 1),
            child: Container(height: h, decoration: BoxDecoration(
              color: cnt > 0 ? _kRed.withValues(alpha: .6) : Colors.grey.withValues(alpha: .2),
              borderRadius: BorderRadius.circular(2))),
          ));
        }).toList()),
      ),
      const SizedBox(height: 16),
      SectionTitle('Top Vulnerable Images'),
      const SizedBox(height: 8),
      ...topImages.map((im) {
        final m = im as Map<String,dynamic>;
        return _tile(icon: Icons.bug_report_outlined, iconColor: _kRed, title: str(m['image']),
          subtitle: '${str(m['cve_critical'],'0')} critical · ${str(m['cve_high'],'0')} high', trailing: 'risk ${str(m['risk'])}');
      }),
      const SizedBox(height: 16),
      SectionTitle('Alerts by Type'),
      const SizedBox(height: 8),
      ...alertByType.map((t) {
        final m = t as Map<String,dynamic>;
        return _tile(icon: Icons.category_outlined, title: str(m['type']).replaceAll('_', ' '), trailing: str(m['count']));
      }),
      const SizedBox(height: 16),
      SectionTitle('Risk by Namespace'),
      const SizedBox(height: 8),
      ...nsRisk.map((ns) {
        final m = ns as Map<String,dynamic>;
        return _tile(icon: Icons.folder_outlined, title: str(m['namespace']),
          subtitle: '${str(m['pods'])} pods', trailing: 'avg risk ${str(m['risk'])}');
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
