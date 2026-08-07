import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── Assets (CMDB) ─────────────────────────────────────────────────────────────

class AssetsScreen extends StatefulWidget {
  final DashboardApi api;
  const AssetsScreen({super.key, required this.api});
  @override State<AssetsScreen> createState() => _AssetsState();
}

class _AssetsState extends State<AssetsScreen> {
  List _assets = [];
  bool _loading = true;
  String _filter = '';

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.assets();
    if (!mounted) return;
    setState(() { _assets = r; _loading = false; });
  }

  List get _filtered => _filter.isEmpty ? _assets : _assets.where((a) {
    final m = a as Map<String,dynamic>;
    final q = _filter.toLowerCase();
    return str(m['hostname']).toLowerCase().contains(q) || str(m['ip_addresses']).toLowerCase().contains(q) || str(m['asset_type']).toLowerCase().contains(q);
  }).toList();

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
          child: TextField(
            decoration: const InputDecoration(labelText: 'Search assets', isDense: true, prefixIcon: Icon(Icons.search)),
            onChanged: (v) => setState(() => _filter = v),
          ),
        ),
        Expanded(child: _filtered.isEmpty ? const XEmptyState('No assets found') : RefreshIndicator(
          onRefresh: _load,
          child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(8, 0, 8, 80),
            itemCount: _filtered.length,
            itemBuilder: (_, i) {
              // ace_assets: hostname/name/asset_type/ip_addresses(plural)/
              // os_name/status — no create/delete endpoint in this system,
              // assets arrive via discovery.
              final a  = _filtered[i] as Map<String,dynamic>;
              return Card(
                margin: const EdgeInsets.only(bottom: 4),
                child: ListTile(
                  leading: _assetIcon(str(a['asset_type'])),
                  title: Text(str(a['hostname'] ?? a['name'], 'Unknown asset'), style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text('${str(a['ip_addresses'], '')}  ·  ${str(a['asset_type'])}  ·  ${str(a['os_name'], '')}', style: const TextStyle(fontSize: 11)),
                  trailing: StatusChip(str(a['status'], 'active')),
                  onTap: () => _showDetail(a),
                ),
              );
            },
          ),
        )),
      ]),
    );
  }

  Widget _assetIcon(String type) {
    final color = switch(type.toLowerCase()) {
      'server'                   => const Color(0xFF3B82F6),
      'workstation' || 'desktop' => const Color(0xFF6366F1),
      'network'                  => const Color(0xFF0EA5E9),
      'mobile'                   => const Color(0xFF22C55E),
      'cloud'                    => const Color(0xFF06B6D4),
      _                          => const Color(0xFF6B7280),
    };
    final icon = switch(type.toLowerCase()) {
      'server'                   => Icons.dns,
      'workstation' || 'desktop' => Icons.computer,
      'network'                  => Icons.router,
      'mobile'                   => Icons.smartphone,
      'cloud'                    => Icons.cloud,
      _                          => Icons.devices,
    };
    return Container(
      width: 36, height: 36,
      decoration: BoxDecoration(
        color: color.withValues(alpha: .1),
        borderRadius: BorderRadius.circular(10),
      ),
      child: Icon(icon, color: color, size: 18),
    );
  }

  void _showDetail(Map<String,dynamic> a) {
    showDetailSheet(context, str(a['hostname'] ?? a['name']), [
      ('Type',          str(a['asset_type'])),
      ('IP Addresses',  str(a['ip_addresses'], '')),
      ('OS',            '${str(a['os_name'], '')} ${str(a['os_version'], '')}'),
      ('Owner',         str(a['owner'], '')),
      ('Business Unit', str(a['business_unit'], '')),
      ('Criticality',   str(a['criticality'], '')),
      ('Location',      str(a['location'], '')),
      ('Status',        str(a['status'], '')),
      ('Managed',       a['managed'] == true ? 'Yes' : 'No'),
      ('Last Seen',     timeAgo(a['last_seen_at'])),
    ], actions: [
      TextButton(
        onPressed: () { Navigator.pop(context); _editAsset(a); },
        child: const Text('Edit'),
      ),
    ]);
  }

  void _editAsset(Map<String,dynamic> a) {
    final assetId = str(a['asset_id']);
    final ownerCtrl = TextEditingController(text: str(a['owner']));
    final locationCtrl = TextEditingController(text: str(a['location']));
    String criticality = str(a['criticality'], 'medium');
    String status = str(a['status'], 'active');
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => SingleChildScrollView(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Edit Asset'),
          xField(ownerCtrl, 'Owner'),
          const SizedBox(height: 10),
          xField(locationCtrl, 'Location'),
          const SizedBox(height: 10),
          xDropdown('Criticality', criticality, ['critical','high','medium','low'], (v) => ss(() => criticality = v!)),
          const SizedBox(height: 10),
          xDropdown('Status', status, ['active','inactive','decommissioned','maintenance'], (v) => ss(() => status = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.updateAsset(assetId, {
                'owner': ownerCtrl.text.trim(), 'location': locationCtrl.text.trim(),
                'criticality': criticality, 'status': status,
              });
              if (context.mounted) xSnack(context, ok ? 'Asset updated' : 'Failed', error: !ok);
              _load();
            },
            child: const Text('Save'),
          )),
        ]),
      )),
    );
  }
}

// ── Mobile (MDM) ──────────────────────────────────────────────────────────────

class MDMScreen extends StatefulWidget {
  final DashboardApi api;
  const MDMScreen({super.key, required this.api});
  @override State<MDMScreen> createState() => _MDMState();
}

class _MDMState extends State<MDMScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _devices = [], _enrollments = [];
  bool _loading = true;

  @override void initState() { super.initState(); _tabs = TabController(length: 2, vsync: this); _load(); }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.mdmDevices(), widget.api.mdmEnrollments()]);
    if (!mounted) return;
    setState(() { _devices = res[0]; _enrollments = res[1]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, tabs: const [Tab(text: 'Devices'), Tab(text: 'Enrollments')]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [_devicesTab(), _enrollmentsTab()])),
    ]);
  }

  Widget _devicesTab() => Scaffold(
    body: _devices.isEmpty ? const XEmptyState('No enrolled devices') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _devices.length,
        itemBuilder: (_, i) {
          final d  = _devices[i] as Map<String,dynamic>;
          final id = d['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: Icon(
                d['platform'] == 'ios' ? Icons.phone_iphone : Icons.phone_android,
                color: statusColor(str(d['status'])),
              ),
              title: Text(str(d['device_name'] ?? d['name'] ?? 'Device $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text(
                '${str(d['platform'])} ${str(d['os_version'])}  ·  ${str(d['status'])}'
                '\n${str(d['serial_number'], '')}',
                style: const TextStyle(fontSize: 11),
              ),
              isThreeLine: true,
              trailing: PopupMenuButton<String>(
                onSelected: (cmd) async {
                  if (cmd == 'lock')     { await widget.api.mdmCommand(id, 'lock', {}); xSnack(context, 'Lock command sent'); }
                  if (cmd == 'apps')     { await widget.api.mdmCommand(id, 'collect_apps', {}); xSnack(context, 'App inventory requested'); }
                  if (cmd == 'logs')     { await widget.api.mdmCommand(id, 'collect_logs', {}); xSnack(context, 'Log collection started'); }
                  if (cmd == 'wipe') {
                    if (context.mounted && await xConfirm(context, 'Remote Wipe', 'Wipe this device? This is irreversible.')) {
                      await widget.api.mdmCommand(id, 'wipe', {});
                      xSnack(context, 'Wipe command sent');
                    }
                  }
                  if (cmd == 'unblock') { await widget.api.mdmUnblock(id); xSnack(context, 'Device unblocked'); _load(); }
                  if (cmd == 'detail')  { _showDeviceDetail(d); }
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'detail',  child: Text('View Details')),
                  PopupMenuDivider(),
                  PopupMenuItem(value: 'apps',    child: Text('Collect App Inventory')),
                  PopupMenuItem(value: 'logs',    child: Text('Collect Logs')),
                  PopupMenuItem(value: 'lock',    child: Text('Lock Device')),
                  PopupMenuItem(value: 'unblock', child: Text('Unblock')),
                  PopupMenuItem(value: 'wipe',    child: Text('Remote Wipe', style: TextStyle(color: Colors.red))),
                ],
              ),
            ),
          );
        },
      ),
    ),
  );

  void _showDeviceDetail(Map<String,dynamic> d) {
    // MDMDevice (services/mdm_service.go) has no `imei` field and no
    // `serial`/`last_checkin`/`last_seen` — the real columns are
    // `serial_number` and `last_check_in`, so those two rows always
    // rendered blank/never before this fix.
    showDetailSheet(context, str(d['device_name'] ?? d['name']), [
      ('Platform',      str(d['platform'])),
      ('OS Version',    str(d['os_version'])),
      ('Model',         str(d['model'] ?? '')),
      ('Serial',        str(d['serial_number'], '')),
      ('Status',        str(d['status'])),
      ('Enrolled',      timeAgo(d['enrolled_at'] ?? d['created_at'])),
      ('Last Check-in', timeAgo(d['last_check_in'])),
    ]);
  }

  Widget _enrollmentsTab() => Scaffold(
    body: _enrollments.isEmpty ? const XEmptyState('No enrollment tokens') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _enrollments.length,
        itemBuilder: (_, i) {
          // EnrollmentToken (services/mdm_mobile_service.go) has no `used`
          // bool or `enrollment_type` string — those fields don't exist on
          // this model, so this row always read "Unused" for every token
          // regardless of real usage. Real fields: `used_count` (int) and
          // `max_uses` (nullable int, null = unlimited).
          final e  = _enrollments[i] as Map<String,dynamic>;
          final id = e['id'] as int? ?? 0;
          final usedCount = (e['used_count'] as num?)?.toInt() ?? 0;
          final maxUses = (e['max_uses'] as num?)?.toInt();
          final exhausted = maxUses != null && usedCount >= maxUses;
          final usageLabel = maxUses != null ? 'Used $usedCount/$maxUses' : 'Used $usedCount×';
          return Card(
            margin: const EdgeInsets.only(bottom: 4),
            child: ListTile(
              leading: Icon(Icons.qr_code, color: exhausted ? Colors.grey : Colors.blue),
              title: Text(str(e['token']), style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
              subtitle: Text('$usageLabel  ·  ${str(e['platform'], '')}  ·  ${timeAgo(e['created_at'])}'),
              trailing: IconButton(
                icon: const Icon(Icons.delete_outline, color: Colors.red),
                onPressed: () async {
                  if (await xConfirm(context, 'Revoke Token', 'Revoke this enrollment token?')) { await widget.api.revokeEnrollment(id); _load(); }
                },
              ),
            ),
          );
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(onPressed: _generateToken, child: const Icon(Icons.add)),
  );

  void _generateToken() async {
    final token = await widget.api.createEnrollmentToken();
    if (!mounted) return;
    if (token != null) {
      showDetailSheet(context, 'Enrollment Token', [
        ('Token', str(token['token'])),
        ('Platform', str(token['platform'], 'android')),
        ('Expires', token['expires_at'] == null ? 'Never' : timeAgo(token['expires_at'])),
      ]);
    }
    _load();
  }
}
