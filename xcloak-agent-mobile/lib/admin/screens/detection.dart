import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── Shared CRUD list scaffold ─────────────────────────────────────────────────

class _ListScreen extends StatefulWidget {
  final Future<List> Function() loader;
  final Widget Function(Map<String,dynamic> item, VoidCallback reload) itemBuilder;
  final Widget? Function()? fabBuilder;
  final String emptyLabel;
  const _ListScreen({required this.loader, required this.itemBuilder, this.fabBuilder, this.emptyLabel = 'No items'});
  @override State<_ListScreen> createState() => _ListScreenState();
}

class _ListScreenState extends State<_ListScreen> {
  List _items = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.loader();
    if (!mounted) return;
    setState(() { _items = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final fab = widget.fabBuilder?.call();
    return Scaffold(
      body: _items.isEmpty
          ? XEmptyState(widget.emptyLabel)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
                itemCount: _items.length,
                itemBuilder: (_, i) => widget.itemBuilder(_items[i] as Map<String,dynamic>, _load),
              ),
            ),
      floatingActionButton: fab,
    );
  }
}

// ── Alerts ────────────────────────────────────────────────────────────────────

class AlertsScreen extends StatefulWidget {
  final DashboardApi api;
  const AlertsScreen({super.key, required this.api});
  @override State<AlertsScreen> createState() => _AlertsState();
}

class _AlertsState extends State<AlertsScreen> {
  List _alerts = [];
  bool _loading = true;
  String _sev = '', _status = '';

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.alerts(sev: _sev, status: _status, per: 50);
    if (!mounted) return;
    setState(() { _alerts = r; _loading = false; });
  }

  void _filter(String sev, String status) { setState(() { _sev = sev; _status = status; }); _load(); }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      SingleChildScrollView(
        scrollDirection: Axis.horizontal,
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 0),
        child: Row(children: [
          for (final f in [('All','',''),('Critical','critical',''),('High','high',''),('Medium','medium',''),('Open','','open')])
            Padding(
              padding: const EdgeInsets.only(right: 6),
              child: FilterChip(
                label: Text(f.$1),
                selected: _sev == f.$2 && _status == f.$3,
                onSelected: (_) => _filter(f.$2, f.$3),
              ),
            ),
        ]),
      ),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else if (_alerts.isEmpty) const Expanded(child: XEmptyState('No alerts'))
      else Expanded(child: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.all(8),
          itemCount: _alerts.length,
          itemBuilder: (_, i) {
            final a      = _alerts[i] as Map<String,dynamic>;
            final id     = a['id'] as int? ?? 0;
            final status = str(a['status']);
            final col    = sevColor(str(a['severity']));
            return Padding(
              padding: const EdgeInsets.only(bottom: 6),
              child: Card(
                child: IntrinsicHeight(
                  child: Row(children: [
                    Container(
                      width: 4,
                      decoration: BoxDecoration(
                        color: col,
                        borderRadius: const BorderRadius.only(
                          topLeft: Radius.circular(12),
                          bottomLeft: Radius.circular(12),
                        ),
                      ),
                    ),
                    Expanded(
                      child: Padding(
                        padding: const EdgeInsets.fromLTRB(10, 10, 6, 10),
                        child: Row(children: [
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text(str(a['rule_name'] ?? a['message']), maxLines: 2, overflow: TextOverflow.ellipsis,
                                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600)),
                            const SizedBox(height: 4),
                            Row(children: [
                              SevChip(str(a['severity'])),
                              const SizedBox(width: 6),
                              Flexible(child: Text(
                                '${str(a['hostname'] ?? '')}  ·  ${timeAgo(a['created_at'])}',
                                style: TextStyle(fontSize: 11, color: Colors.grey.shade500),
                                overflow: TextOverflow.ellipsis,
                              )),
                            ]),
                          ])),
                          if (status == 'open')
                            PopupMenuButton<String>(
                              onSelected: (v) async {
                                final ok = v == 'ack' ? await widget.api.ackAlert(id) : await widget.api.resolveAlert(id);
                                if (context.mounted) xSnack(context, ok ? 'Done' : 'Failed', error: !ok);
                                if (ok) _load();
                              },
                              itemBuilder: (_) => const [
                                PopupMenuItem(value: 'ack',     child: Text('Acknowledge')),
                                PopupMenuItem(value: 'resolve', child: Text('Resolve')),
                              ],
                            )
                          else
                            Padding(padding: const EdgeInsets.only(right: 4), child: StatusChip(status)),
                        ]),
                      ),
                    ),
                  ]),
                ),
              ),
            );
          },
        ),
      )),
    ]);
  }
}

// ── Incidents ─────────────────────────────────────────────────────────────────

class IncidentsScreen extends StatefulWidget {
  final DashboardApi api;
  const IncidentsScreen({super.key, required this.api});
  @override State<IncidentsScreen> createState() => _IncidentsState();
}

class _IncidentsState extends State<IncidentsScreen> {
  List _items = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.incidents(per: 50);
    if (!mounted) return;
    setState(() { _items = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_items.isEmpty) return const XEmptyState('No incidents');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _items.length,
        itemBuilder: (_, i) {
          final inc = _items[i] as Map<String,dynamic>;
          final id  = inc['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: SevChip(str(inc['severity'])),
              title: Text(str(inc['title'] ?? 'Incident $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text('${str(inc['status']).toUpperCase()}  ·  ${timeAgo(inc['created_at'])}', style: const TextStyle(fontSize: 11)),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == '__note') { _addNote(id); return; }
                  final ok = await widget.api.updateIncidentStatus(id, v);
                  if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                  if (ok) _load();
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'investigating', child: Text('Investigating')),
                  PopupMenuItem(value: 'contained',     child: Text('Contained')),
                  PopupMenuItem(value: 'resolved',      child: Text('Resolve')),
                  PopupMenuItem(value: 'closed',        child: Text('Close')),
                  PopupMenuDivider(),
                  PopupMenuItem(value: '__note',        child: Text('Add Note')),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  void _addNote(int id) {
    final ctrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Add Note'),
          xField(ctrl, 'Note', maxLines: 4),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.addIncidentNote(id, ctrl.text.trim());
              if (context.mounted) xSnack(context, 'Note added');
            },
            child: const Text('Save'),
          )),
        ]),
      ),
    );
  }
}

// ── UEBA ──────────────────────────────────────────────────────────────────────

class UEBAScreen extends StatefulWidget {
  final DashboardApi api;
  const UEBAScreen({super.key, required this.api});
  @override State<UEBAScreen> createState() => _UEBAState();
}

class _UEBAState extends State<UEBAScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _users = [], _events = [];
  bool _loading = true;

  @override void initState() { super.initState(); _tabs = TabController(length: 2, vsync: this); _load(); }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.uebaUsers(), widget.api.uebaEvents()]);
    if (!mounted) return;
    setState(() { _users = res[0]; _events = res[1]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, tabs: const [Tab(text: 'Users'), Tab(text: 'Events')]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _userList(),
        _eventList(),
      ])),
    ]);
  }

  Widget _userList() => _users.isEmpty ? const XEmptyState('No UEBA users') : RefreshIndicator(
    onRefresh: _load,
    child: ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _users.length,
      itemBuilder: (_, i) {
        final u = _users[i] as Map<String,dynamic>;
        return Card(child: ListTile(
          leading: CircleAvatar(child: Text(str(u['username'] ?? u['user_id'], '?')[0].toUpperCase())),
          title: Text(str(u['username'] ?? u['user_id'])),
          subtitle: Text('Risk: ${str(u['risk_score'])}  ·  ${timeAgo(u['last_seen'] ?? u['last_activity'])}'),
          trailing: SevChip(str(u['risk_level'] ?? 'low')),
        ));
      },
    ),
  );

  Widget _eventList() => _events.isEmpty ? const XEmptyState('No UEBA events') : RefreshIndicator(
    onRefresh: _load,
    child: ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _events.length,
      itemBuilder: (_, i) {
        final e = _events[i] as Map<String,dynamic>;
        return Card(child: ListTile(
          dense: true,
          leading: Icon(Icons.warning_amber, color: sevColor(str(e['severity']))),
          title: Text(str(e['event_type'] ?? e['action']), style: const TextStyle(fontSize: 13)),
          subtitle: Text('${str(e['username'] ?? e['user'])}  ·  ${timeAgo(e['timestamp'] ?? e['created_at'])}'),
        ));
      },
    ),
  );
}

// ── Insider Threat ────────────────────────────────────────────────────────────

class InsiderThreatScreen extends StatefulWidget {
  final DashboardApi api;
  const InsiderThreatScreen({super.key, required this.api});
  @override State<InsiderThreatScreen> createState() => _InsiderThreatState();
}

class _InsiderThreatState extends State<InsiderThreatScreen> {
  List _scores = [];
  Map<String,dynamic>? _summary;
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.insiderThreat(), widget.api.insiderSummary()]);
    if (!mounted) return;
    setState(() { _scores = res[0] as List; _summary = res[1] as Map<String,dynamic>?; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final s = _summary ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(8),
        children: [
          if (s.isNotEmpty) StatRow([
            ('High Risk Users', str(s['high_risk_users'] ?? s['high_risk'] ?? 0), Colors.red),
            ('Total Monitored', str(s['total_users'] ?? s['monitored'] ?? 0), Colors.blue),
          ]),
          const SizedBox(height: 8),
          ..._scores.map((item) {
            final u = item as Map<String,dynamic>;
            return Card(
              margin: const EdgeInsets.only(bottom: 6),
              child: ListTile(
                leading: CircleAvatar(backgroundColor: sevColor(str(u['risk_level'])), child: Text(str(u['username'] ?? u['user_id'], '?')[0].toUpperCase(), style: const TextStyle(color: Colors.white))),
                title: Text(str(u['username'] ?? u['user_id'])),
                subtitle: Text('Score: ${str(u['risk_score'])}  ·  ${str(u['department'] ?? '')}'),
                trailing: SevChip(str(u['risk_level'] ?? 'low')),
              ),
            );
          }),
        ],
      ),
    );
  }
}

// ── ITDR (AD Attacks / Cloud / Email / etc.) ──────────────────────────────────

class ItdrScreen extends StatefulWidget {
  final DashboardApi api;
  final String category, title;
  const ItdrScreen({super.key, required this.api, required this.category, required this.title});
  @override State<ItdrScreen> createState() => _ItdrState();
}

class _ItdrState extends State<ItdrScreen> {
  List _items = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.itdrFindings(category: widget.category);
    if (!mounted) return;
    setState(() { _items = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_items.isEmpty) return XEmptyState('No ${widget.title} findings');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _items.length,
        itemBuilder: (_, i) {
          final f = _items[i] as Map<String,dynamic>;
          final id = f['id'] as int? ?? 0;
          return Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: SevChip(str(f['severity'])),
              title: Text(str(f['title'] ?? f['finding_type']), style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text('${str(f['status'])}  ·  ${str(f['affected_entity'] ?? '')}  ·  ${timeAgo(f['detected_at'] ?? f['created_at'])}', style: const TextStyle(fontSize: 11)),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  final ok = await widget.api.updateItdrStatus(id, v);
                  if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                  if (ok) _load();
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'investigating', child: Text('Investigating')),
                  PopupMenuItem(value: 'resolved',      child: Text('Resolve')),
                  PopupMenuItem(value: 'false_positive',child: Text('False Positive')),
                ],
              ),
            ),
          );
        },
      ),
    );
  }
}

// ── Deception (Canary + Honeyport) ────────────────────────────────────────────

class DeceptionScreen extends StatefulWidget {
  final DashboardApi api;
  const DeceptionScreen({super.key, required this.api});
  @override State<DeceptionScreen> createState() => _DeceptionState();
}

class _DeceptionState extends State<DeceptionScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _canary = [], _trips = [], _honey = [];
  bool _loading = true;

  @override void initState() { super.initState(); _tabs = TabController(length: 3, vsync: this); _load(); }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.canaryTokens(), widget.api.canaryTrips(), widget.api.honeyports()]);
    if (!mounted) return;
    setState(() { _canary = res[0]; _trips = res[1]; _honey = res[2]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, tabs: const [Tab(text: 'Canary Tokens'), Tab(text: 'Trips'), Tab(text: 'Honeyports')]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _canaryTab(),
        _tripsTab(),
        _honeyTab(),
      ])),
    ]);
  }

  Widget _canaryTab() => Scaffold(
    body: _canary.isEmpty ? const XEmptyState('No canary tokens') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _canary.length,
        itemBuilder: (_, i) {
          final t = _canary[i] as Map<String,dynamic>;
          final enabled = t['enabled'] as bool? ?? t['is_active'] as bool? ?? false;
          return Card(child: ListTile(
            leading: Icon(Icons.link, color: enabled ? Colors.green : Colors.grey),
            title: Text(str(t['name'])),
            subtitle: Text('${str(t['token_type'] ?? t['type'])}  ·  ${str(t['trips'] ?? 0)} trips'),
            trailing: PopupMenuButton<String>(
              onSelected: (v) async {
                final id = t['id'] as int? ?? 0;
                if (v == 'toggle') await widget.api.toggleCanary(id);
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete', 'Delete this canary token?')) {
                    await widget.api.deleteCanary(id);
                  }
                }
                _load();
              },
              itemBuilder: (_) => [
                PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
              ],
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(
      onPressed: _createCanary,
      child: const Icon(Icons.add),
    ),
  );

  void _createCanary() {
    final nameCtrl = TextEditingController();
    String type = 'url';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Create Canary Token'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['url', 'dns', 'file', 'email'], (v) => ss(() => type = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createCanary({'name': nameCtrl.text.trim(), 'token_type': type, 'description': ''});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  Widget _tripsTab() => _trips.isEmpty ? const XEmptyState('No trips recorded') : RefreshIndicator(
    onRefresh: _load,
    child: ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _trips.length,
      itemBuilder: (_, i) {
        final t = _trips[i] as Map<String,dynamic>;
        return Card(child: ListTile(
          leading: const Icon(Icons.warning, color: Colors.orange),
          title: Text(str(t['token_name'] ?? t['name'])),
          subtitle: Text('IP: ${str(t['src_ip'] ?? t['ip'])}  ·  ${timeAgo(t['tripped_at'] ?? t['created_at'])}'),
        ));
      },
    ),
  );

  Widget _honeyTab() => Scaffold(
    body: _honey.isEmpty ? const XEmptyState('No honeyports') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _honey.length,
        itemBuilder: (_, i) {
          final h = _honey[i] as Map<String,dynamic>;
          return Card(child: ListTile(
            leading: Icon(Icons.podcasts, color: statusColor(str(h['status'] ?? 'active'))),
            title: Text('Port ${str(h['port'])} / ${str(h['protocol'])}'),
            subtitle: Text(str(h['description'])),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline, color: Colors.red),
              onPressed: () async {
                if (await xConfirm(context, 'Delete', 'Delete honeyport?')) {
                  await widget.api.deleteHoneyport(h['id'] as int? ?? 0);
                  _load();
                }
              },
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(
      onPressed: _createHoneyport,
      child: const Icon(Icons.add),
    ),
  );

  void _createHoneyport() {
    final portCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    String proto = 'tcp';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Create Honeyport'),
          xField(portCtrl, 'Port', keyboardType: TextInputType.number),
          const SizedBox(height: 10),
          xDropdown('Protocol', proto, ['tcp', 'udp'], (v) => ss(() => proto = v!)),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createHoneyport({'port': int.tryParse(portCtrl.text) ?? 0, 'protocol': proto, 'description': descCtrl.text.trim()});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Net Behavior ──────────────────────────────────────────────────────────────

class NetBehaviorScreen extends StatefulWidget {
  final DashboardApi api;
  const NetBehaviorScreen({super.key, required this.api});
  @override State<NetBehaviorScreen> createState() => _NetBehaviorState();
}

class _NetBehaviorState extends State<NetBehaviorScreen> {
  List _items = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.nbaAnomalies();
    if (!mounted) return;
    setState(() { _items = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_items.isEmpty) return const XEmptyState('No network anomalies');
    return Scaffold(
      body: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.all(8),
          itemCount: _items.length,
          itemBuilder: (_, i) {
            final a = _items[i] as Map<String,dynamic>;
            final id = a['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: SevChip(str(a['severity'])),
              title: Text(str(a['anomaly_type'] ?? a['type']), style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text('${str(a['src_ip'] ?? a['agent_id'])}  ·  ${timeAgo(a['detected_at'] ?? a['created_at'])}'),
              trailing: str(a['status']) == 'open' ? TextButton(
                onPressed: () async { await widget.api.ackNbaAnomaly(id); _load(); },
                child: const Text('Ack'),
              ) : StatusChip(str(a['status'])),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async { await widget.api.triggerNBA(); xSnack(context, 'NBA analysis triggered'); },
        icon: const Icon(Icons.analytics),
        label: const Text('Analyze'),
      ),
    );
  }
}

// ── Behavioral ────────────────────────────────────────────────────────────────

class BehavioralScreen extends StatefulWidget {
  final DashboardApi api;
  const BehavioralScreen({super.key, required this.api});
  @override State<BehavioralScreen> createState() => _BehavioralState();
}

class _BehavioralState extends State<BehavioralScreen> {
  List _scores = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.threatScores();
    if (!mounted) return;
    setState(() { _scores = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_scores.isEmpty) return const XEmptyState('No behavioral anomalies');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _scores.length,
        itemBuilder: (_, i) {
          final s = _scores[i] as Map<String,dynamic>;
          return Card(child: ListTile(
            leading: CircleAvatar(backgroundColor: sevColor(str(s['risk_level'] ?? 'low')), radius: 16, child: Text('${s['score'] ?? 0}', style: const TextStyle(color: Colors.white, fontSize: 11))),
            title: Text(str(s['hostname'] ?? s['agent_id'])),
            subtitle: Text('Score: ${str(s['score'])}  ·  ${str(s['risk_level'] ?? 'unknown').toUpperCase()}'),
            trailing: str(s['status']) == 'open'
                ? TextButton(
                    onPressed: () async { await widget.api.ackThreatFinding(s['id'] as int? ?? 0); _load(); },
                    child: const Text('Ack'),
                  )
                : null,
          ));
        },
      ),
    );
  }
}

// ── Live Logs ─────────────────────────────────────────────────────────────────

class LiveLogsScreen extends StatefulWidget {
  final DashboardApi api;
  const LiveLogsScreen({super.key, required this.api});
  @override State<LiveLogsScreen> createState() => _LiveLogsState();
}

class _LiveLogsState extends State<LiveLogsScreen> {
  final List<Map<String,dynamic>> _logs = [];
  bool _paused = false;
  late final Stream<void> _ticker;
  final _scroll = ScrollController();

  @override
  void initState() {
    super.initState();
    _poll();
    _ticker = Stream.periodic(const Duration(seconds: 5));
    _ticker.listen((_) { if (!_paused && mounted) _poll(); });
  }

  @override void dispose() { _scroll.dispose(); super.dispose(); }

  Future<void> _poll() async {
    final r = await widget.api.liveEvents();
    if (!mounted) return;
    setState(() {
      for (final e in r) {
        final m = e as Map<String,dynamic>;
        if (!_logs.any((l) => l['id'] == m['id'])) _logs.insert(0, m);
      }
      if (_logs.length > 200) _logs.removeRange(200, _logs.length);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: PreferredSize(
        preferredSize: const Size.fromHeight(40),
        child: Row(
          children: [
            const SizedBox(width: 12),
            OnlineDot(!_paused),
            const SizedBox(width: 6),
            Text(_paused ? 'Paused' : 'Live', style: const TextStyle(fontSize: 12)),
            const Spacer(),
            TextButton.icon(
              onPressed: () => setState(() => _paused = !_paused),
              icon: Icon(_paused ? Icons.play_arrow : Icons.pause),
              label: Text(_paused ? 'Resume' : 'Pause'),
            ),
            TextButton(onPressed: () => setState(() => _logs.clear()), child: const Text('Clear')),
          ],
        ),
      ),
      body: _logs.isEmpty
          ? const XEmptyState('Waiting for events…')
          : ListView.builder(
              controller: _scroll,
              padding: const EdgeInsets.all(4),
              itemCount: _logs.length,
              itemBuilder: (_, i) {
                final l = _logs[i];
                return Container(
                  margin: const EdgeInsets.only(bottom: 2),
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: Theme.of(context).colorScheme.surfaceVariant,
                    borderRadius: BorderRadius.circular(4),
                  ),
                  child: Row(children: [
                    Container(width: 3, height: 30, color: sevColor(str(l['severity'])), margin: const EdgeInsets.only(right: 8)),
                    Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text(str(l['event_type'] ?? l['type'] ?? l['action']), style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w600)),
                      Text(str(l['message'] ?? l['description']), style: const TextStyle(fontSize: 11, color: Colors.grey), maxLines: 1, overflow: TextOverflow.ellipsis),
                    ])),
                    Text(timeAgo(l['timestamp'] ?? l['created_at']), style: const TextStyle(fontSize: 10, color: Colors.grey)),
                  ]),
                );
              },
            ),
    );
  }
}

// ── Alert Clusters ────────────────────────────────────────────────────────────

class AlertClustersScreen extends StatefulWidget {
  final DashboardApi api;
  const AlertClustersScreen({super.key, required this.api});
  @override State<AlertClustersScreen> createState() => _AlertClustersState();
}

class _AlertClustersState extends State<AlertClustersScreen> {
  List _items = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.clusters();
    if (!mounted) return;
    setState(() { _items = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_items.isEmpty) return const XEmptyState('No alert clusters');
    return Scaffold(
      body: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.all(8),
          itemCount: _items.length,
          itemBuilder: (_, i) {
            final c = _items[i] as Map<String,dynamic>;
            final id = c['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: CircleAvatar(child: Text('${c['size'] ?? c['alert_count'] ?? 0}', style: const TextStyle(fontSize: 11))),
              title: Text(str(c['label'] ?? c['pattern'] ?? 'Cluster $id')),
              subtitle: Text('${str(c['alert_count'] ?? c['size'] ?? 0)} alerts  ·  ${timeAgo(c['created_at'])}'),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'suppress') { await widget.api.suppressCluster(id); _load(); }
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'suppress', child: Text('Suppress Cluster')),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async { await widget.api.triggerClustering(); xSnack(context, 'Clustering triggered'); },
        icon: const Icon(Icons.analytics),
        label: const Text('Re-cluster'),
      ),
    );
  }
}

// ── Correlation ───────────────────────────────────────────────────────────────

class CorrelationScreen extends StatefulWidget {
  final DashboardApi api;
  const CorrelationScreen({super.key, required this.api});
  @override State<CorrelationScreen> createState() => _CorrelationState();
}

class _CorrelationState extends State<CorrelationScreen> {
  List _rules = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.correlationRules();
    if (!mounted) return;
    setState(() { _rules = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _rules.isEmpty ? const XEmptyState('No correlation rules') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _rules.length,
          itemBuilder: (_, i) {
            final r = _rules[i] as Map<String,dynamic>;
            final id      = r['id'] as int? ?? 0;
            final enabled = r['enabled'] as bool? ?? r['is_enabled'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.compare_arrows, color: enabled ? Colors.green : Colors.grey),
              title: Text(str(r['name'])),
              subtitle: Text('${str(r['severity'])}  ·  ${str(r['window_seconds'] ?? 0)}s window  ·  ${r['match_count'] ?? 0} hits'),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'toggle') await widget.api.toggleCorrelationRule(id);
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete', 'Delete this rule?')) await widget.api.deleteCorrelationRule(id);
                  }
                  _load();
                },
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
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
    final nameCtrl  = TextEditingController();
    final queryCtrl = TextEditingController();
    String sev = 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Correlation Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xField(queryCtrl, 'Query', maxLines: 3),
          const SizedBox(height: 10),
          xDropdown('Severity', sev, ['critical','high','medium','low'], (v) => ss(() => sev = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createCorrelationRule({'name': nameCtrl.text.trim(), 'query': queryCtrl.text.trim(), 'severity': sev, 'window_seconds': 300});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Suppression ───────────────────────────────────────────────────────────────

class SuppressionScreen extends StatefulWidget {
  final DashboardApi api;
  const SuppressionScreen({super.key, required this.api});
  @override State<SuppressionScreen> createState() => _SuppressionState();
}

class _SuppressionState extends State<SuppressionScreen> {
  List _rules = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.suppressionRules();
    if (!mounted) return;
    setState(() { _rules = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _rules.isEmpty ? const XEmptyState('No suppression rules') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _rules.length,
          itemBuilder: (_, i) {
            final r = _rules[i] as Map<String,dynamic>;
            final id      = r['id'] as int? ?? 0;
            final enabled = r['enabled'] as bool? ?? r['is_active'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.volume_off, color: enabled ? Colors.orange : Colors.grey),
              title: Text(str(r['name'])),
              subtitle: Text('${str(r['field'])}: ${str(r['value'])}', style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'toggle') await widget.api.toggleSuppression(id);
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete', 'Delete suppression rule?')) await widget.api.deleteSuppression(id);
                  }
                  _load();
                },
                itemBuilder: (_) => [
                  PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
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
    final nameCtrl  = TextEditingController();
    final fieldCtrl = TextEditingController();
    final valCtrl   = TextEditingController();
    final reasonCtrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Suppression Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xField(fieldCtrl, 'Field (e.g. hostname)'),
          const SizedBox(height: 10),
          xField(valCtrl, 'Value'),
          const SizedBox(height: 10),
          xField(reasonCtrl, 'Reason'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createSuppressionRule({'name': nameCtrl.text.trim(), 'field': fieldCtrl.text.trim(), 'value': valCtrl.text.trim(), 'reason': reasonCtrl.text.trim()});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      ),
    );
  }
}
