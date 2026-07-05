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
    return str(m['hostname']).toLowerCase().contains(q) || str(m['ip_address']).toLowerCase().contains(q) || str(m['asset_type']).toLowerCase().contains(q);
  }).toList();

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: Column(children: [
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 8, 12, 4),
          child: TextField(
            decoration: const InputDecoration(labelText: 'Search assets', border: OutlineInputBorder(), isDense: true, prefixIcon: Icon(Icons.search)),
            onChanged: (v) => setState(() => _filter = v),
          ),
        ),
        Expanded(child: _filtered.isEmpty ? const XEmptyState('No assets found') : RefreshIndicator(
          onRefresh: _load,
          child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(8, 0, 8, 80),
            itemCount: _filtered.length,
            itemBuilder: (_, i) {
              final a  = _filtered[i] as Map<String,dynamic>;
              final id = a['id'] as int? ?? 0;
              return Card(
                margin: const EdgeInsets.only(bottom: 4),
                child: ListTile(
                  leading: _assetIcon(str(a['asset_type'] ?? a['type'])),
                  title: Text(str(a['hostname'] ?? a['name'] ?? 'Asset $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
                  subtitle: Text('${str(a['ip_address'] ?? '')}  ·  ${str(a['asset_type'] ?? a['type'] ?? '')}  ·  ${str(a['os'] ?? '')}', style: const TextStyle(fontSize: 11)),
                  trailing: StatusChip(str(a['status'] ?? 'active')),
                  onTap: () => _showDetail(a),
                ),
              );
            },
          ),
        )),
      ]),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  Widget _assetIcon(String type) {
    final color = switch(type.toLowerCase()) {
      'server'   => Colors.blue,
      'workstation' || 'desktop' => Colors.indigo,
      'network'  => Colors.teal,
      'mobile'   => Colors.green,
      'cloud'    => Colors.cyan,
      _          => Colors.grey,
    };
    final icon = switch(type.toLowerCase()) {
      'server'          => Icons.dns,
      'workstation' || 'desktop' => Icons.computer,
      'network'         => Icons.router,
      'mobile'          => Icons.smartphone,
      'cloud'           => Icons.cloud,
      _                 => Icons.devices,
    };
    return Icon(icon, color: color);
  }

  void _showDetail(Map<String,dynamic> a) {
    showDetailSheet(context, str(a['hostname'] ?? a['name']), [
      ('Type',          str(a['asset_type'] ?? a['type'])),
      ('IP Address',    str(a['ip_address'])),
      ('MAC Address',   str(a['mac_address'] ?? '')),
      ('OS',            str(a['os'] ?? '')),
      ('Owner',         str(a['owner'] ?? '')),
      ('Location',      str(a['location'] ?? '')),
      ('Status',        str(a['status'] ?? '')),
      ('Last Seen',     timeAgo(a['last_seen'] ?? a['updated_at'])),
    ], actions: [
      TextButton(
        onPressed: () async {
          Navigator.pop(context);
          if (await xConfirm(context, 'Delete Asset', 'Delete this asset from CMDB?')) {
            await widget.api.deleteAsset(a['id'] as int? ?? 0);
            _load();
          }
        },
        child: const Text('Delete', style: TextStyle(color: Colors.red)),
      ),
    ]);
  }

  void _create() {
    final nameCtrl  = TextEditingController();
    final ipCtrl    = TextEditingController();
    final ownerCtrl = TextEditingController();
    String type = 'workstation', status = 'active';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => SingleChildScrollView(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Asset', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Hostname / Name'),
          const SizedBox(height: 10),
          xField(ipCtrl, 'IP Address', keyboardType: TextInputType.numberWithOptions(decimal: true)),
          const SizedBox(height: 10),
          xDropdown('Asset Type', type, ['workstation','server','network','mobile','cloud','other'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xDropdown('Status', status, ['active','inactive','decommissioned','maintenance'], (v) => ss(() => status = v!)),
          const SizedBox(height: 10),
          xField(ownerCtrl, 'Owner'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createAsset({'hostname': nameCtrl.text.trim(), 'ip_address': ipCtrl.text.trim(), 'asset_type': type, 'status': status, 'owner': ownerCtrl.text.trim()});
              _load();
            },
            child: const Text('Create'),
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
                '\n${str(d['imei'] ?? d['serial'] ?? '')}',
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
    showDetailSheet(context, str(d['device_name'] ?? d['name']), [
      ('Platform',      str(d['platform'])),
      ('OS Version',    str(d['os_version'])),
      ('Model',         str(d['model'] ?? '')),
      ('IMEI',          str(d['imei'] ?? '')),
      ('Serial',        str(d['serial'] ?? '')),
      ('Status',        str(d['status'])),
      ('Enrolled',      timeAgo(d['enrolled_at'] ?? d['created_at'])),
      ('Last Check-in', timeAgo(d['last_checkin'] ?? d['last_seen'])),
    ]);
  }

  Widget _enrollmentsTab() => Scaffold(
    body: _enrollments.isEmpty ? const XEmptyState('No enrollment tokens') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _enrollments.length,
        itemBuilder: (_, i) {
          final e  = _enrollments[i] as Map<String,dynamic>;
          final id = e['id'] as int? ?? 0;
          final used = e['used'] as bool? ?? false;
          return Card(
            margin: const EdgeInsets.only(bottom: 4),
            child: ListTile(
              leading: Icon(Icons.qr_code, color: used ? Colors.grey : Colors.blue),
              title: Text(str(e['token'] ?? e['enrollment_token']), style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
              subtitle: Text('${used ? "Used" : "Unused"}  ·  ${str(e['enrollment_type'] ?? '')}  ·  ${timeAgo(e['created_at'])}'),
              trailing: used ? null : IconButton(
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
    final token = await widget.api.createEnrollmentToken('corporate');
    if (!mounted) return;
    if (token != null) {
      showDetailSheet(context, 'Enrollment Token', [
        ('Token', str(token['token'] ?? token['enrollment_token'])),
        ('Type',  str(token['enrollment_type'] ?? 'corporate')),
        ('Expires', timeAgo(token['expires_at'])),
      ]);
    }
    _load();
  }
}
