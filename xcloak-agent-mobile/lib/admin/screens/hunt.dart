import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── Hunt Workbench ────────────────────────────────────────────────────────────

class HuntWorkbenchScreen extends StatefulWidget {
  final DashboardApi api;
  const HuntWorkbenchScreen({super.key, required this.api});
  @override State<HuntWorkbenchScreen> createState() => _HuntWorkbenchState();
}

class _HuntWorkbenchState extends State<HuntWorkbenchScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _templates = [], _runs = [], _agents = [];
  bool _loading = true;

  @override void initState() { super.initState(); _tabs = TabController(length: 2, vsync: this); _load(); }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.huntTemplates(), widget.api.huntRuns(), widget.api.agents()]);
    if (!mounted) return;
    setState(() { _templates = res[0]; _runs = res[1]; _agents = res[2]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, tabs: const [Tab(text: 'Templates'), Tab(text: 'Runs')]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [_templatesTab(), _runsTab()])),
    ]);
  }

  Widget _templatesTab() => Scaffold(
    body: _templates.isEmpty ? const XEmptyState('No hunt templates') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _templates.length,
        itemBuilder: (_, i) {
          final t = _templates[i] as Map<String,dynamic>;
          final id = t['id'] as int? ?? 0;
          return Card(child: ListTile(
            leading: const Icon(Icons.travel_explore),
            title: Text(str(t['name'])),
            subtitle: Text('${str(t['platform'] ?? 'any')}  ·  ${str(t['description'] ?? '')}', maxLines: 1, overflow: TextOverflow.ellipsis),
            trailing: PopupMenuButton<String>(
              onSelected: (v) async {
                if (v == 'run') _executeHunt(id);
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete Template', 'Delete this hunt template?')) {
                    await widget.api.deleteHuntTemplate(id);
                    _load();
                  }
                }
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'run',    child: Text('Execute Hunt')),
                PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
              ],
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(onPressed: _createTemplate, child: const Icon(Icons.add)),
  );

  void _createTemplate() {
    final nameCtrl  = TextEditingController();
    final descCtrl  = TextEditingController();
    final queryCtrl = TextEditingController();
    String platform = 'any';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Hunt Template'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 10),
          xField(queryCtrl, 'Query', maxLines: 3),
          const SizedBox(height: 10),
          xDropdown('Platform', platform, ['any','windows','linux','macos'], (v) => ss(() => platform = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createHuntTemplate({'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim(), 'query': queryCtrl.text.trim(), 'platform': platform});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  void _executeHunt(int templateId) {
    final selectedAgents = <int>{};
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Select Agents'),
          SizedBox(
            height: 200,
            child: ListView(children: _agents.map((a) {
              final m = a as Map<String,dynamic>; final id = m['id'] as int? ?? 0;
              return CheckboxListTile(
                title: Text(str(m['hostname'])),
                value: selectedAgents.contains(id),
                onChanged: (v) => ss(() { if (v!) selectedAgents.add(id); else selectedAgents.remove(id); }),
              );
            }).toList()),
          ),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.executeHunt(templateId, selectedAgents.toList());
              if (context.mounted) xSnack(context, 'Hunt started');
              _load();
            },
            child: const Text('Execute'),
          )),
        ]),
      )),
    );
  }

  Widget _runsTab() => _runs.isEmpty ? const XEmptyState('No hunt runs') : RefreshIndicator(
    onRefresh: _load,
    child: ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _runs.length,
      itemBuilder: (_, i) {
        final r = _runs[i] as Map<String,dynamic>;
        return Card(child: ListTile(
          leading: Icon(Icons.check_circle, color: statusColor(str(r['status']))),
          title: Text(str(r['template_name'] ?? r['name'] ?? 'Hunt ${r['id']}')),
          subtitle: Text('${str(r['status'])}  ·  ${r['results_count'] ?? 0} results  ·  ${timeAgo(r['started_at'] ?? r['created_at'])}'),
        ));
      },
    ),
  );
}

// ── Threat Actors ─────────────────────────────────────────────────────────────

class ThreatActorsScreen extends StatefulWidget {
  final DashboardApi api;
  const ThreatActorsScreen({super.key, required this.api});
  @override State<ThreatActorsScreen> createState() => _ThreatActorsState();
}

class _ThreatActorsState extends State<ThreatActorsScreen> {
  List _actors = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.threatActors();
    if (!mounted) return;
    setState(() { _actors = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _actors.isEmpty ? const XEmptyState('No threat actors') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _actors.length,
          itemBuilder: (_, i) {
            final a = _actors[i] as Map<String,dynamic>;
            final id = a['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: CircleAvatar(backgroundColor: Colors.red.shade800, child: Text(str(a['name'], 'A')[0].toUpperCase(), style: const TextStyle(color: Colors.white))),
              title: Text(str(a['name'])),
              subtitle: Text('${str(a['aliases'] ?? '')}  ·  ${str(a['alert_count'] ?? 0)} alerts', maxLines: 1),
              trailing: IconButton(
                icon: const Icon(Icons.delete_outline, color: Colors.red),
                onPressed: () async {
                  if (await xConfirm(context, 'Delete Actor', 'Delete this threat actor?')) {
                    await widget.api.deleteThreatActor(id);
                    _load();
                  }
                },
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
    final descCtrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Threat Actor'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description', maxLines: 3),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createThreatActor({'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim(), 'aliases': [], 'tags': []});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      ),
    );
  }
}

// ── Threat Intel (IOCs + Threat Feeds) ───────────────────────────────────────

class ThreatIntelScreen extends StatefulWidget {
  final DashboardApi api;
  const ThreatIntelScreen({super.key, required this.api});
  @override State<ThreatIntelScreen> createState() => _ThreatIntelState();
}

class _ThreatIntelState extends State<ThreatIntelScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _iocs = [], _feeds = [];
  bool _loading = true;

  @override void initState() { super.initState(); _tabs = TabController(length: 2, vsync: this); _load(); }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.iocs(), widget.api.threatFeeds()]);
    if (!mounted) return;
    setState(() { _iocs = res[0]; _feeds = res[1]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, tabs: const [Tab(text: 'IOCs'), Tab(text: 'Feeds')]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [_iocsTab(), _feedsTab()])),
    ]);
  }

  Widget _iocsTab() => Scaffold(
    body: _iocs.isEmpty ? const XEmptyState('No IOCs') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _iocs.length,
        itemBuilder: (_, i) {
          final ioc = _iocs[i] as Map<String,dynamic>;
          final id      = ioc['id'] as int? ?? 0;
          final enabled = ioc['enabled'] as bool? ?? ioc['is_enabled'] as bool? ?? false;
          return Card(child: ListTile(
            leading: SevChip(str(ioc['severity'])),
            title: Text(str(ioc['value']), style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
            subtitle: Text('${str(ioc['type'])}  ·  ${str(ioc['description'] ?? '')}', maxLines: 1),
            trailing: PopupMenuButton<String>(
              onSelected: (v) async {
                if (v == 'toggle') await widget.api.toggleIoc(id, !enabled);
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete IOC', 'Delete this IOC?')) await widget.api.deleteIoc(id);
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
    floatingActionButton: FloatingActionButton(onPressed: _createIoc, child: const Icon(Icons.add)),
  );

  void _createIoc() {
    final valCtrl  = TextEditingController();
    final descCtrl = TextEditingController();
    String type = 'ip', sev = 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New IOC'),
          xField(valCtrl, 'Value (IP/Domain/Hash)'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['ip','domain','hash','url','email'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xDropdown('Severity', sev, ['critical','high','medium','low'], (v) => ss(() => sev = v!)),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createIoc({'type': type, 'value': valCtrl.text.trim(), 'severity': sev, 'description': descCtrl.text.trim()});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  Widget _feedsTab() => Scaffold(
    body: _feeds.isEmpty ? const XEmptyState('No threat feeds') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _feeds.length,
        itemBuilder: (_, i) {
          final f = _feeds[i] as Map<String,dynamic>;
          final id      = f['id'] as int? ?? 0;
          final enabled = f['enabled'] as bool? ?? f['is_enabled'] as bool? ?? false;
          return Card(child: ListTile(
            leading: Icon(Icons.rss_feed, color: enabled ? Colors.green : Colors.grey),
            title: Text(str(f['name'])),
            subtitle: Text('${str(f['format'] ?? '')}  ·  Last sync: ${timeAgo(f['last_synced_at'])}'),
            trailing: PopupMenuButton<String>(
              onSelected: (v) async {
                if (v == 'sync')   { await widget.api.syncThreatFeed(id); xSnack(context, 'Sync started'); }
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete', 'Delete this feed?')) await widget.api.deleteThreatFeed(id);
                }
                _load();
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'sync',   child: Text('Sync Now')),
                PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
              ],
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(onPressed: _createFeed, child: const Icon(Icons.add)),
  );

  void _createFeed() {
    final nameCtrl = TextEditingController();
    final urlCtrl  = TextEditingController();
    String format = 'stix';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Threat Feed'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(urlCtrl, 'URL', keyboardType: TextInputType.url),
          const SizedBox(height: 10),
          xDropdown('Format', format, ['stix','misp','csv','txt'], (v) => ss(() => format = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createThreatFeed({'name': nameCtrl.text.trim(), 'url': urlCtrl.text.trim(), 'format': format, 'enabled': true});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Sigma Rules ───────────────────────────────────────────────────────────────

class SigmaRulesScreen extends StatefulWidget {
  final DashboardApi api;
  const SigmaRulesScreen({super.key, required this.api});
  @override State<SigmaRulesScreen> createState() => _SigmaRulesState();
}

class _SigmaRulesState extends State<SigmaRulesScreen> {
  List _rules = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.sigmaRules();
    if (!mounted) return;
    setState(() { _rules = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _rules.isEmpty ? const XEmptyState('No Sigma rules') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _rules.length,
          itemBuilder: (_, i) {
            final r = _rules[i] as Map<String,dynamic>;
            final id      = r['id'] as int? ?? 0;
            final enabled = r['enabled'] as bool? ?? r['is_enabled'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.rule, color: enabled ? Colors.green : Colors.grey),
              title: Text(str(r['name'] ?? r['title'])),
              subtitle: Text('${str(r['severity'] ?? r['level'])}  ·  ${str(r['category'] ?? r['source'] ?? '')}', style: const TextStyle(fontSize: 11)),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'toggle') { await widget.api.toggleSigma(id, !enabled); _load(); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Rule', 'Delete this Sigma rule?')) { await widget.api.deleteSigma(id); _load(); }
                  }
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
    final nameCtrl    = TextEditingController();
    final contentCtrl = TextEditingController();
    String sev = 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Sigma Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xDropdown('Severity', sev, ['critical','high','medium','low'], (v) => ss(() => sev = v!)),
          const SizedBox(height: 10),
          xField(contentCtrl, 'YAML Content', maxLines: 6),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createSigma({'name': nameCtrl.text.trim(), 'content': contentCtrl.text.trim(), 'severity': sev, 'enabled': true});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── YARA Rules ────────────────────────────────────────────────────────────────

class YaraRulesScreen extends StatefulWidget {
  final DashboardApi api;
  const YaraRulesScreen({super.key, required this.api});
  @override State<YaraRulesScreen> createState() => _YaraRulesState();
}

class _YaraRulesState extends State<YaraRulesScreen> {
  List _rules = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.yaraRules();
    if (!mounted) return;
    setState(() { _rules = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _rules.isEmpty ? const XEmptyState('No YARA rules') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _rules.length,
          itemBuilder: (_, i) {
            final r = _rules[i] as Map<String,dynamic>;
            final id      = r['id'] as int? ?? 0;
            final enabled = r['enabled'] as bool? ?? r['is_enabled'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.pest_control, color: enabled ? Colors.green : Colors.grey),
              title: Text(str(r['name'])),
              subtitle: Text('${r['match_count'] ?? 0} matches  ·  ${timeAgo(r['created_at'])}'),
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'toggle') { await widget.api.toggleYara(id, !enabled); _load(); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Rule', 'Delete this YARA rule?')) { await widget.api.deleteYara(id); _load(); }
                  }
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
    final nameCtrl    = TextEditingController();
    final contentCtrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New YARA Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xField(contentCtrl, 'Rule Content', maxLines: 8),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createYara({'name': nameCtrl.text.trim(), 'content': contentCtrl.text.trim(), 'enabled': true});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      ),
    );
  }
}

// ── JA3 Fingerprints ──────────────────────────────────────────────────────────

class JA3Screen extends StatefulWidget {
  final DashboardApi api;
  const JA3Screen({super.key, required this.api});
  @override State<JA3Screen> createState() => _JA3State();
}

class _JA3State extends State<JA3Screen> {
  List _fps = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.ja3Fingerprints();
    if (!mounted) return;
    setState(() { _fps = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _fps.isEmpty ? const XEmptyState('No JA3 fingerprints') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _fps.length,
          itemBuilder: (_, i) {
            final f = _fps[i] as Map<String,dynamic>;
            final id = f['id'] as int? ?? 0;
            final bad = f['is_malicious'] as bool? ?? false;
            return Card(child: ListTile(
              leading: Icon(Icons.fingerprint, color: bad ? Colors.red : Colors.grey),
              title: Text(str(f['fingerprint']), style: const TextStyle(fontFamily: 'monospace', fontSize: 11)),
              subtitle: Text('${str(f['label'] ?? '')}  ·  ${bad ? "MALICIOUS" : "benign"}'),
              trailing: IconButton(
                icon: const Icon(Icons.delete_outline, color: Colors.red),
                onPressed: () async {
                  if (await xConfirm(context, 'Delete', 'Delete fingerprint?')) { await widget.api.deleteJa3(id); _load(); }
                },
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  void _create() {
    final fpCtrl    = TextEditingController();
    final labelCtrl = TextEditingController();
    bool malicious  = true;
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New JA3 Fingerprint'),
          xField(fpCtrl, 'JA3 Hash (MD5)'),
          const SizedBox(height: 10),
          xField(labelCtrl, 'Label (e.g. Cobalt Strike)'),
          const SizedBox(height: 10),
          SwitchListTile(title: const Text('Mark as Malicious'), value: malicious, onChanged: (v) => ss(() => malicious = v)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createJa3({'fingerprint': fpCtrl.text.trim(), 'label': labelCtrl.text.trim(), 'is_malicious': malicious});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Log Search ────────────────────────────────────────────────────────────────

class LogSearchScreen extends StatefulWidget {
  final DashboardApi api;
  const LogSearchScreen({super.key, required this.api});
  @override State<LogSearchScreen> createState() => _LogSearchState();
}

class _LogSearchState extends State<LogSearchScreen> {
  final _qCtrl = TextEditingController();
  List _results = [], _saved = [];
  bool _searching = false;

  @override void initState() { super.initState(); _loadSaved(); }
  @override void dispose() { _qCtrl.dispose(); super.dispose(); }

  Future<void> _loadSaved() async {
    final r = await widget.api.savedSearches();
    if (!mounted) return;
    setState(() => _saved = r);
  }

  Future<void> _search() async {
    if (_qCtrl.text.trim().isEmpty) return;
    setState(() => _searching = true);
    final r = await widget.api.searchLogs(q: _qCtrl.text.trim(), limit: 100);
    if (!mounted) return;
    setState(() { _results = r; _searching = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.all(12),
        child: Row(children: [
          Expanded(child: TextField(
            controller: _qCtrl,
            decoration: const InputDecoration(labelText: 'Search query', border: OutlineInputBorder(), isDense: true, prefixIcon: Icon(Icons.search)),
            onSubmitted: (_) => _search(),
          )),
          const SizedBox(width: 8),
          FilledButton(onPressed: _search, child: const Text('Search')),
        ]),
      ),
      if (_saved.isNotEmpty) ...[
        Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12),
          child: Row(children: [
            const Text('SAVED', style: TextStyle(fontSize: 11, color: Colors.grey, letterSpacing: 1.2)),
            const Spacer(),
            TextButton.icon(icon: const Icon(Icons.save, size: 14), label: const Text('Save', style: TextStyle(fontSize: 12)),
              onPressed: () async {
                if (_qCtrl.text.trim().isEmpty) return;
                await widget.api.saveSearch('Search ${DateTime.now().millisecondsSinceEpoch}', _qCtrl.text.trim());
                _loadSaved();
              },
            ),
          ]),
        ),
        SizedBox(height: 40, child: ListView.separated(
          scrollDirection: Axis.horizontal,
          padding: const EdgeInsets.symmetric(horizontal: 12),
          itemCount: _saved.length,
          separatorBuilder: (_, __) => const SizedBox(width: 6),
          itemBuilder: (_, i) {
            final s = _saved[i] as Map<String,dynamic>;
            return Chip(
              label: Text(str(s['name']), style: const TextStyle(fontSize: 12)),
              onDeleted: () async { await widget.api.deleteSavedSearch(s['id'] as int? ?? 0); _loadSaved(); },
              deleteIcon: const Icon(Icons.close, size: 14),
            );
          },
        )),
      ],
      if (_searching) const Padding(padding: EdgeInsets.all(20), child: CircularProgressIndicator())
      else if (_results.isEmpty) const Expanded(child: XEmptyState('Run a search to see results'))
      else Expanded(child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _results.length,
        itemBuilder: (_, i) {
          final l = _results[i] as Map<String,dynamic>;
          return Card(child: Padding(
            padding: const EdgeInsets.all(10),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                StatusChip(str(l['level'] ?? l['severity'])),
                const SizedBox(width: 8),
                Text(timeAgo(l['timestamp'] ?? l['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
                const Spacer(),
                Text(str(l['hostname'] ?? l['agent_id']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ]),
              const SizedBox(height: 4),
              Text(str(l['message'] ?? l['raw']), style: const TextStyle(fontSize: 12, fontFamily: 'monospace'), maxLines: 3, overflow: TextOverflow.ellipsis),
            ]),
          ));
        },
      )),
    ]);
  }
}

// ── Log Sources ───────────────────────────────────────────────────────────────

class LogSourcesScreen extends StatefulWidget {
  final DashboardApi api;
  const LogSourcesScreen({super.key, required this.api});
  @override State<LogSourcesScreen> createState() => _LogSourcesState();
}

class _LogSourcesState extends State<LogSourcesScreen> {
  List _sources = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.logSources();
    if (!mounted) return;
    setState(() { _sources = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _sources.isEmpty ? const XEmptyState('No log sources') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _sources.length,
          itemBuilder: (_, i) {
            final s = _sources[i] as Map<String,dynamic>;
            final id = s['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: Icon(Icons.source, color: statusColor(str(s['status'] ?? 'active'))),
              title: Text(str(s['name'])),
              subtitle: Text('${str(s['type'])}  ·  ${str(s['host'] ?? '')}:${str(s['port'] ?? '')}'),
              trailing: IconButton(
                icon: const Icon(Icons.delete_outline, color: Colors.red),
                onPressed: () async {
                  if (await xConfirm(context, 'Delete Source', 'Delete this log source?')) { await widget.api.deleteLogSource(id); _load(); }
                },
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
    final hostCtrl = TextEditingController();
    final portCtrl = TextEditingController();
    String type = 'syslog', proto = 'udp';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Log Source'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['syslog','winlog','filebeat','json','csv'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xField(hostCtrl, 'Host / IP'),
          const SizedBox(height: 10),
          Row(children: [
            Expanded(child: xField(portCtrl, 'Port', keyboardType: TextInputType.number)),
            const SizedBox(width: 10),
            Expanded(child: xDropdown('Protocol', proto, ['udp','tcp','tls'], (v) => ss(() => proto = v!))),
          ]),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createLogSource({'name': nameCtrl.text.trim(), 'type': type, 'host': hostCtrl.text.trim(), 'port': int.tryParse(portCtrl.text) ?? 514, 'protocol': proto});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ── Threat Hunt ───────────────────────────────────────────────────────────────

class ThreatHuntScreen extends StatefulWidget {
  final DashboardApi api;
  const ThreatHuntScreen({super.key, required this.api});
  @override State<ThreatHuntScreen> createState() => _ThreatHuntState();
}

class _ThreatHuntState extends State<ThreatHuntScreen> {
  List _runs = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.huntRuns();
    if (!mounted) return;
    setState(() { _runs = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_runs.isEmpty) return const XEmptyState('No threat hunt runs — start from Hunt Workbench');
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.all(8),
        itemCount: _runs.length,
        itemBuilder: (_, i) {
          final r = _runs[i] as Map<String,dynamic>;
          return Card(child: ListTile(
            leading: Icon(Icons.travel_explore, color: statusColor(str(r['status']))),
            title: Text(str(r['template_name'] ?? r['name'] ?? 'Hunt ${r['id']}')),
            subtitle: Text('${str(r['status'])}  ·  ${r['results_count'] ?? 0} results  ·  ${timeAgo(r['started_at'] ?? r['created_at'])}'),
            trailing: r['results_count'] != null && (r['results_count'] as int) > 0
                ? const Icon(Icons.warning, color: Colors.orange)
                : null,
          ));
        },
      ),
    );
  }
}

// ── ITDR Threat-Category Screen ───────────────────────────────────────────────

class ItdrScreen extends StatefulWidget {
  final DashboardApi api;
  final String       category;
  final String       title;
  const ItdrScreen({super.key, required this.api, required this.category, required this.title});
  @override State<ItdrScreen> createState() => _ItdrState();
}

class _ItdrState extends State<ItdrScreen> {
  List _items   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.get('/api/itdr/findings?type=${widget.category}');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['items'] ?? []) : []);
    setState(() { _items = list as List; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return _loading ? xLoading() : _items.isEmpty
      ? XEmptyState('No ${widget.title} detections', icon: Icons.radar_outlined)
      : RefreshIndicator(
          onRefresh: _load,
          child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
            itemCount: _items.length,
            itemBuilder: (_, i) {
              final d = _items[i] as Map<String,dynamic>;
              return Card(
                margin: const EdgeInsets.only(bottom: 8),
                child: ListTile(
                  leading: SevChip(str(d['severity'])),
                  title: Text(str(d['title'] ?? d['name']),
                    style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700)),
                  subtitle: Text('${str(d['status'])}  ·  ${timeAgo(d['created_at'])}',
                    style: const TextStyle(fontSize: 12)),
                  trailing: StatusChip(str(d['status'])),
                ),
              );
            },
          ),
        );
  }
}

// ── Deception / Honeypots Screen ──────────────────────────────────────────────

class DeceptionScreen extends StatefulWidget {
  final DashboardApi api;
  const DeceptionScreen({super.key, required this.api});
  @override State<DeceptionScreen> createState() => _DeceptionState();
}

class _DeceptionState extends State<DeceptionScreen> {
  List _traps   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.get('/api/honeyports');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['honeyports'] ?? []) : []);
    setState(() { _traps = list as List; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
        child: SectionTitle('Honeypots & Deception Traps  (${_traps.length})'),
      ),
      Expanded(child: _loading ? xLoading() : _traps.isEmpty
        ? const XEmptyState('No deception traps configured', icon: Icons.pest_control)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
              itemCount: _traps.length,
              itemBuilder: (_, i) {
                final t = _traps[i] as Map<String,dynamic>;
                final active = t['active'] == true || t['enabled'] == true;
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Icon(Icons.pest_control,
                      color: active ? const Color(0xFF6366F1) : Colors.grey),
                    title: Text(str(t['name'] ?? t['hostname']),
                      style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Text('Type: ${str(t['type'] ?? t['trap_type'])}  ·  '
                      'Interactions: ${t['interactions'] ?? t['hit_count'] ?? 0}'),
                    trailing: Switch(
                      value: active,
                      onChanged: (v) async {
                        // honeyports have no toggle endpoint — create/delete to enable/disable
                        _load();
                      },
                    ),
                  ),
                );
              },
            ),
          )),
    ]);
  }
}

// ── Behavioral Analytics Screen ───────────────────────────────────────────────

class BehavioralScreen extends StatefulWidget {
  final DashboardApi api;
  const BehavioralScreen({super.key, required this.api});
  @override State<BehavioralScreen> createState() => _BehavioralState();
}

class _BehavioralState extends State<BehavioralScreen> {
  Map  _summary = {};
  List _baselines = [];
  bool _loading   = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final bRes = await widget.api.get('/api/threat/baselines');
    final aRes = await widget.api.get('/api/ai/anomalies');
    if (!mounted) return;
    final baselines = bRes is List ? bRes : (bRes is Map ? (bRes['baselines'] ?? bRes['data'] ?? []) : []);
    final anomalies = aRes is List ? aRes : (aRes is Map ? (aRes['anomalies'] ?? aRes['data'] ?? []) : []);
    final s = <String,dynamic>{
      'anomalies_today': (anomalies as List).length,
      'active_models': baselines is List ? baselines.length : 0,
    };
    setState(() { _summary = s; _baselines = baselines as List; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 80),
        children: [
          Row(children: [
            Expanded(child: KpiCard(label: 'Baselines', value: '${_baselines.length}', icon: Icons.analytics, color: const Color(0xFF6366F1))),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Anomalies Today', value: '${_summary['anomalies_today'] ?? 0}', icon: Icons.warning_amber, color: const Color(0xFFF59E0B))),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Active Models', value: '${_summary['active_models'] ?? 0}', icon: Icons.model_training, color: const Color(0xFF22C55E))),
          ]),
          const SizedBox(height: 16),
          SectionTitle('Behavioral Baselines'),
          ..._baselines.map((b) {
            final base = b as Map<String,dynamic>;
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.timeline, color: Color(0xFF6366F1)),
                title: Text(str(base['entity_type'] ?? base['type']),
                  style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('Entity: ${str(base['entity_id'])}  ·  '
                  'Last updated: ${timeAgo(base['updated_at'])}'),
                trailing: Text('${base['deviation_score'] ?? '-'}',
                  style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 15)),
              ),
            );
          }),
          if (_baselines.isEmpty)
            const Padding(
              padding: EdgeInsets.all(32),
              child: Center(child: Text('No behavioral baselines yet',
                style: TextStyle(color: Colors.grey))),
            ),
        ],
      ),
    );
  }
}

// ── Live Logs Screen ──────────────────────────────────────────────────────────

class LiveLogsScreen extends StatefulWidget {
  final DashboardApi api;
  const LiveLogsScreen({super.key, required this.api});
  @override State<LiveLogsScreen> createState() => _LiveLogsState();
}

class _LiveLogsState extends State<LiveLogsScreen> {
  List _logs    = [];
  bool _loading = true;
  bool _live    = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    if (!_live) return;
    setState(() => _loading = _logs.isEmpty);
    final r = await widget.api.get('/api/logs/search?per_page=200&q=');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['logs'] ?? []) : []);
    setState(() { _logs = list as List; _loading = false; });
    if (_live) Future.delayed(const Duration(seconds: 5), _load);
  }

  @override void dispose() { _live = false; super.dispose(); }

  Color _levelColor(String level) => switch (level.toLowerCase()) {
    'critical' || 'fatal' => const Color(0xFFEF4444),
    'error'               => const Color(0xFFF97316),
    'warn' || 'warning'   => const Color(0xFFF59E0B),
    'debug'               => Colors.grey,
    _                     => const Color(0xFF22C55E),
  };

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 8, 12, 0),
        child: Row(children: [
          Icon(_live ? Icons.wifi : Icons.wifi_off,
            size: 14, color: _live ? const Color(0xFF22C55E) : Colors.grey),
          const SizedBox(width: 6),
          Text(_live ? 'Live' : 'Paused',
            style: TextStyle(fontSize: 12, color: _live ? const Color(0xFF22C55E) : Colors.grey,
              fontWeight: FontWeight.w700)),
          const Spacer(),
          TextButton(
            onPressed: () { setState(() => _live = !_live); if (_live) _load(); },
            child: Text(_live ? 'Pause' : 'Resume'),
          ),
        ]),
      ),
      Expanded(child: _loading ? xLoading() :
        ListView.builder(
          reverse: true,
          padding: const EdgeInsets.fromLTRB(8, 4, 8, 80),
          itemCount: _logs.length,
          itemBuilder: (_, i) {
            final log = _logs[i] as Map<String,dynamic>;
            final level = str(log['level'] ?? log['severity'] ?? 'info');
            return Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                border: Border(bottom: BorderSide(color: Colors.grey.withOpacity(.08)))),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(level.toUpperCase().padRight(5),
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800,
                    color: _levelColor(level), fontFamily: 'monospace')),
                const SizedBox(width: 8),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(str(log['message'] ?? log['msg']),
                    style: const TextStyle(fontSize: 12, fontFamily: 'monospace')),
                  Text(str(log['source'] ?? log['host'] ?? ''),
                    style: const TextStyle(fontSize: 10, color: Colors.grey)),
                ])),
                Text(timeAgo(log['timestamp'] ?? log['created_at']),
                  style: const TextStyle(fontSize: 10, color: Colors.grey)),
              ]),
            );
          },
        )),
    ]);
  }
}

// ── Vulnerabilities Screen ────────────────────────────────────────────────────

class VulnerabilitiesScreen extends StatefulWidget {
  final DashboardApi api;
  const VulnerabilitiesScreen({super.key, required this.api});
  @override State<VulnerabilitiesScreen> createState() => _VulnerabilitiesState();
}

class _VulnerabilitiesState extends State<VulnerabilitiesScreen> {
  List   _vulns    = [];
  bool   _loading  = true;
  String _sevFilter = '';

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.get('/api/vulns/priority-queue${_sevFilter.isNotEmpty ? "?severity=$_sevFilter" : ""}');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['vulnerabilities'] ?? []) : []);
    setState(() { _vulns = list as List; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      FilterRow(
        selected: _sevFilter,
        onSelect: (v) { setState(() => _sevFilter = v); _load(); },
        chips: const [
          ('All', '', null), ('Critical', 'critical', null), ('High', 'high', null),
          ('Medium', 'medium', null), ('Low', 'low', null),
        ],
      ),
      Expanded(child: _loading ? xLoading() : _vulns.isEmpty
        ? const XEmptyState('No vulnerabilities found', icon: Icons.verified_user_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
              itemCount: _vulns.length,
              itemBuilder: (_, i) {
                final v = _vulns[i] as Map<String,dynamic>;
                final cvss = (v['cvss_score'] ?? v['score'] ?? 0.0);
                final sev  = str(v['severity']);
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: SevChip(sev),
                    title: Text(str(v['cve_id'] ?? v['vuln_id'] ?? v['title']),
                      style: const TextStyle(fontWeight: FontWeight.w800, fontFamily: 'monospace')),
                    subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text(str(v['title'] ?? v['description']),
                        maxLines: 2, overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 12)),
                      const SizedBox(height: 2),
                      Text('CVSS: $cvss  ·  ${timeAgo(v['discovered_at'] ?? v['created_at'])}',
                        style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    ]),
                    trailing: SevChip(sev),
                    isThreeLine: true,
                  ),
                );
              },
            ),
          )),
    ]);
  }
}

// ── Firewall Rules Screen ─────────────────────────────────────────────────────

class FirewallScreen extends StatefulWidget {
  final DashboardApi api;
  const FirewallScreen({super.key, required this.api});
  @override State<FirewallScreen> createState() => _FirewallState();
}

class _FirewallState extends State<FirewallScreen> {
  List _rules   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.get('/api/firewall/rules');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['rules'] ?? []) : []);
    setState(() { _rules = list as List; _loading = false; });
  }

  Color _actionColor(String action) => switch (action.toLowerCase()) {
    'block' || 'deny' || 'drop' => const Color(0xFFEF4444),
    'allow' || 'accept'         => const Color(0xFF22C55E),
    _                           => const Color(0xFFF59E0B),
  };

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      floatingActionButton: FloatingActionButton(
        onPressed: () => xSnack(context, 'Rule creation coming soon'),
        child: const Icon(Icons.add),
      ),
      body: _loading ? xLoading() : _rules.isEmpty
        ? const XEmptyState('No firewall rules configured', icon: Icons.fireplace_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
              itemCount: _rules.length,
              itemBuilder: (_, i) {
                final rule = _rules[i] as Map<String, dynamic>;
                final action = str(rule['action']);
                final enabled = rule['enabled'] == true || rule['active'] == true;
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Container(
                      padding: const EdgeInsets.all(6),
                      decoration: BoxDecoration(
                        color: _actionColor(action).withOpacity(.12),
                        borderRadius: BorderRadius.circular(8)),
                      child: Icon(
                        action.toLowerCase() == 'block' || action.toLowerCase() == 'deny'
                          ? Icons.block : Icons.check_circle_outline,
                        color: _actionColor(action), size: 20),
                    ),
                    title: Text(str(rule['name'] ?? rule['description'] ?? 'Rule ${rule['id']}'),
                      style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Text(
                      '${str(rule['src_ip'] ?? rule['source'] ?? '*')} → '
                      '${str(rule['dst_ip'] ?? rule['destination'] ?? '*')}  '
                      'Port: ${rule['port'] ?? rule['dst_port'] ?? '*'}',
                      style: const TextStyle(fontSize: 11.5, fontFamily: 'monospace')),
                    trailing: Switch(
                      value: enabled,
                      onChanged: (v) async {
                        await widget.api.patch('/api/firewall/rules/${rule['id']}', {'enabled': v});
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

// ── Script Runner Screen ──────────────────────────────────────────────────────

class ScriptRunnerScreen extends StatefulWidget {
  final DashboardApi api;
  const ScriptRunnerScreen({super.key, required this.api});
  @override State<ScriptRunnerScreen> createState() => _ScriptRunnerState();
}

class _ScriptRunnerState extends State<ScriptRunnerScreen> {
  List   _scripts = [];
  List   _history = [];
  bool   _loading = true;
  String _tab     = 'scripts';

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final scripts = await widget.api.get('/api/sigma/rules');
    final history = await widget.api.get('/api/hunt/runs');
    if (!mounted) return;
    final sl = scripts is List ? scripts : (scripts is Map ? (scripts['data'] ?? scripts['rules'] ?? []) : []);
    final hl = history is List ? history : (history is Map ? (history['data'] ?? history['runs'] ?? []) : []);
    setState(() { _scripts = sl as List; _history = hl as List; _loading = false; });
  }

  Future<void> _run(Map<String,dynamic> script) async {
    xSnack(context, 'Running ${str(script['name'])}…');
    final ok = await widget.api.post('/api/hunt/execute', {'rule_id': script['id'], 'agent_ids': []});
    if (mounted) xSnack(context, ok == null ? 'Execution failed' : 'Hunt started', error: ok == null);
    _load();
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(children: [
          ChoiceChip(label: const Text('Scripts'), selected: _tab == 'scripts',
            onSelected: (_) => setState(() => _tab = 'scripts')),
          const SizedBox(width: 8),
          ChoiceChip(label: const Text('History'), selected: _tab == 'history',
            onSelected: (_) => setState(() => _tab = 'history')),
        ]),
      ),
      Expanded(child: _loading ? xLoading() : _tab == 'scripts'
        ? _scripts.isEmpty
          ? const XEmptyState('No scripts configured', icon: Icons.code_off)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
                itemCount: _scripts.length,
                itemBuilder: (_, i) {
                  final s = _scripts[i] as Map<String,dynamic>;
                  return Card(
                    margin: const EdgeInsets.only(bottom: 8),
                    child: ListTile(
                      leading: Container(
                        padding: const EdgeInsets.all(8),
                        decoration: BoxDecoration(
                          color: const Color(0xFF6366F1).withOpacity(.1),
                          borderRadius: BorderRadius.circular(8)),
                        child: const Icon(Icons.terminal, color: Color(0xFF6366F1), size: 20),
                      ),
                      title: Text(str(s['name']),
                        style: const TextStyle(fontWeight: FontWeight.w700)),
                      subtitle: Text(str(s['description'] ?? s['language'] ?? ''),
                        style: const TextStyle(fontSize: 12)),
                      trailing: FilledButton(
                        onPressed: () => _run(s),
                        style: FilledButton.styleFrom(
                          backgroundColor: const Color(0xFF6366F1),
                          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8)),
                        child: const Text('Run', style: TextStyle(fontSize: 12.5)),
                      ),
                    ),
                  );
                },
              ),
            )
        : _history.isEmpty
          ? const XEmptyState('No script history', icon: Icons.history_toggle_off)
          : ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
              itemCount: _history.length,
              itemBuilder: (_, i) {
                final h = _history[i] as Map<String,dynamic>;
                final status = str(h['status']);
                final ok = status == 'success' || status == 'completed';
                return Card(
                  margin: const EdgeInsets.only(bottom: 6),
                  child: ListTile(
                    leading: Icon(ok ? Icons.check_circle : Icons.error_outline,
                      color: ok ? const Color(0xFF22C55E) : const Color(0xFFEF4444)),
                    title: Text(str(h['script_name'] ?? h['name']),
                      style: const TextStyle(fontWeight: FontWeight.w600)),
                    subtitle: Text('${str(h['executed_by'] ?? h['user'] ?? 'system')}  ·  ${timeAgo(h['executed_at'] ?? h['created_at'])}'),
                    trailing: StatusChip(status),
                  ),
                );
              },
            )),
    ]);
  }
}
