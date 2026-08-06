import 'dart:convert';

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
            subtitle: Text(str(t['description'] ?? ''), maxLines: 1, overflow: TextOverflow.ellipsis),
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
          xField(queryCtrl, 'KQL Query', maxLines: 3),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              // models.HuntTemplate (backend) has no platform field, and the
              // query column is kql_query, not query — the platform picker
              // used to send did nothing, and the query text was silently
              // discarded on every save.
              await widget.api.createHuntTemplate({'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim(), 'kql_query': queryCtrl.text.trim()});
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
          subtitle: Text('${str(r['status'])}  ·  ${r['hit_count'] ?? 0} hits  ·  ${timeAgo(r['started_at'] ?? r['created_at'])}'),
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
              trailing: PopupMenuButton<String>(
                onSelected: (v) async {
                  if (v == 'edit') { _create(existing: a); return; }
                  if (v == 'delete') {
                    if (await xConfirm(context, 'Delete Actor', 'Delete this threat actor?')) {
                      await widget.api.deleteThreatActor(id);
                      _load();
                    }
                  }
                },
                itemBuilder: (_) => const [
                  PopupMenuItem(value: 'edit', child: Text('Edit')),
                  PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: () => _create(), child: const Icon(Icons.add)),
    );
  }

  void _create({Map<String,dynamic>? existing}) {
    final nameCtrl = TextEditingController(text: existing != null ? str(existing['name']) : '');
    final descCtrl = TextEditingController(text: existing != null ? str(existing['description']) : '');
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader(existing != null ? 'Edit Threat Actor' : 'New Threat Actor'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description', maxLines: 3),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = existing != null
                ? await widget.api.updateThreatActor(existing['id'] as int? ?? 0, {'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim()})
                : await widget.api.createThreatActor({'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim(), 'aliases': [], 'tags': []});
              if (context.mounted) xSnack(context, ok ? (existing != null ? 'Actor updated' : 'Actor created') : 'Failed', error: !ok);
              _load();
            },
            child: Text(existing != null ? 'Save' : 'Create'),
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
                if (v == 'edit')   { _iocForm(existing: ioc); return; }
                if (v == 'toggle') await widget.api.toggleIoc(id, !enabled);
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete IOC', 'Delete this IOC?')) await widget.api.deleteIoc(id);
                }
                _load();
              },
              itemBuilder: (_) => [
                const PopupMenuItem(value: 'edit', child: Text('Edit')),
                PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
              ],
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(onPressed: () => _iocForm(), child: const Icon(Icons.add)),
  );

  void _iocForm({Map<String,dynamic>? existing}) {
    final valCtrl  = TextEditingController(text: existing != null ? str(existing['value']) : '');
    final descCtrl = TextEditingController(text: existing != null ? str(existing['description']) : '');
    String type = existing != null ? str(existing['type'], 'ip') : 'ip';
    String sev  = existing != null ? str(existing['severity'], 'high') : 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader(existing != null ? 'Edit IOC' : 'New IOC'),
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
              final body = {'type': type, 'value': valCtrl.text.trim(), 'severity': sev, 'description': descCtrl.text.trim()};
              final ok = existing != null
                ? await widget.api.updateIoc(existing['id'] as int? ?? 0, body)
                : await widget.api.createIoc(body);
              if (context.mounted) xSnack(context, ok ? (existing != null ? 'IOC updated' : 'IOC created') : 'Failed', error: !ok);
              _load();
            },
            child: Text(existing != null ? 'Save' : 'Create'),
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
                if (v == 'edit')   { _feedForm(existing: f); return; }
                if (v == 'sync')   { await widget.api.syncThreatFeed(id); if (context.mounted) xSnack(context, 'Sync started'); }
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete', 'Delete this feed?')) await widget.api.deleteThreatFeed(id);
                }
                _load();
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'edit',   child: Text('Edit')),
                PopupMenuItem(value: 'sync',   child: Text('Sync Now')),
                PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
              ],
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(onPressed: () => _feedForm(), child: const Icon(Icons.add)),
  );

  void _feedForm({Map<String,dynamic>? existing}) {
    final nameCtrl = TextEditingController(text: existing != null ? str(existing['name']) : '');
    final urlCtrl  = TextEditingController(text: existing != null ? str(existing['url']) : '');
    String format = existing != null ? str(existing['format'], 'stix') : 'stix';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader(existing != null ? 'Edit Threat Feed' : 'New Threat Feed'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(urlCtrl, 'URL', keyboardType: TextInputType.url),
          const SizedBox(height: 10),
          xDropdown('Format', format, ['stix','misp','csv','txt'], (v) => ss(() => format = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final body = {'name': nameCtrl.text.trim(), 'url': urlCtrl.text.trim(), 'format': format, 'enabled': true};
              final ok = existing != null
                ? await widget.api.updateThreatFeed(existing['id'] as int? ?? 0, body)
                : await widget.api.createThreatFeed(body);
              if (context.mounted) xSnack(context, ok ? (existing != null ? 'Feed updated' : 'Feed created') : 'Failed', error: !ok);
              _load();
            },
            child: Text(existing != null ? 'Save' : 'Create'),
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
                  if (v == 'edit')   { _create(existing: r); return; }
                  if (v == 'toggle') { await widget.api.toggleSigma(id, !enabled); _load(); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Rule', 'Delete this Sigma rule?')) { await widget.api.deleteSigma(id); _load(); }
                  }
                },
                itemBuilder: (_) => [
                  const PopupMenuItem(value: 'edit', child: Text('Edit')),
                  PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: () => _create(), child: const Icon(Icons.add)),
    );
  }

  void _create({Map<String,dynamic>? existing}) {
    final nameCtrl    = TextEditingController(text: existing != null ? str(existing['name'] ?? existing['title']) : '');
    final contentCtrl = TextEditingController(text: existing != null ? str(existing['content']) : '');
    String sev = existing != null ? str(existing['severity'] ?? existing['level'], 'high') : 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader(existing != null ? 'Edit Sigma Rule' : 'New Sigma Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xDropdown('Severity', sev, ['critical','high','medium','low'], (v) => ss(() => sev = v!)),
          const SizedBox(height: 10),
          xField(contentCtrl, 'YAML Content', maxLines: 6),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final body = {'name': nameCtrl.text.trim(), 'content': contentCtrl.text.trim(), 'severity': sev, 'enabled': true};
              final ok = existing != null
                ? await widget.api.updateSigma(existing['id'] as int? ?? 0, body)
                : await widget.api.createSigma(body);
              if (context.mounted) xSnack(context, ok ? (existing != null ? 'Rule updated' : 'Rule created') : 'Failed', error: !ok);
              _load();
            },
            child: Text(existing != null ? 'Save' : 'Create'),
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
                  if (v == 'edit')   { _create(existing: r); return; }
                  if (v == 'toggle') { await widget.api.toggleYara(id, !enabled); _load(); }
                  if (v == 'delete') {
                    if (context.mounted && await xConfirm(context, 'Delete Rule', 'Delete this YARA rule?')) { await widget.api.deleteYara(id); _load(); }
                  }
                },
                itemBuilder: (_) => [
                  const PopupMenuItem(value: 'edit', child: Text('Edit')),
                  PopupMenuItem(value: 'toggle', child: Text(enabled ? 'Disable' : 'Enable')),
                  const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                ],
              ),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: () => _create(), child: const Icon(Icons.add)),
    );
  }

  void _create({Map<String,dynamic>? existing}) {
    final nameCtrl    = TextEditingController(text: existing != null ? str(existing['name']) : '');
    final contentCtrl = TextEditingController(text: existing != null ? str(existing['content']) : '');
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader(existing != null ? 'Edit YARA Rule' : 'New YARA Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xField(contentCtrl, 'Rule Content', maxLines: 8),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final body = {'name': nameCtrl.text.trim(), 'content': contentCtrl.text.trim(), 'enabled': true};
              final ok = existing != null
                ? await widget.api.updateYara(existing['id'] as int? ?? 0, body)
                : await widget.api.createYara(body);
              if (context.mounted) xSnack(context, ok ? (existing != null ? 'Rule updated' : 'Rule created') : 'Failed', error: !ok);
              _load();
            },
            child: Text(existing != null ? 'Save' : 'Create'),
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
  bool _aiBusy    = false;

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

  Future<void> _askAI() async {
    final qCtrl = TextEditingController();
    final question = await showDialog<String>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: const Text('Ask AI'),
        content: TextField(controller: qCtrl, maxLines: 2,
          decoration: const InputDecoration(hintText: 'e.g. failed logins from an unusual country')),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          FilledButton(onPressed: () => Navigator.pop(ctx, qCtrl.text.trim()), child: const Text('Generate')),
        ],
      ),
    );
    if (question == null || question.isEmpty) return;
    setState(() => _aiBusy = true);
    final r = await widget.api.aiLogQuery(question);
    if (!mounted) return;
    setState(() => _aiBusy = false);
    if (r == null || r['error'] != null) {
      xSnack(context, r?['error'] != null ? str(r!['error']) : 'AI query failed', error: true);
      return;
    }
    _qCtrl.text = str(r['query']);
    _search();
  }

  Future<void> _explainResults() async {
    if (_results.isEmpty) return;
    setState(() => _aiBusy = true);
    final samples = _results.take(10).map((l) => str((l as Map)['message'] ?? l['raw'])).toList();
    final r = await widget.api.aiLogExplain(_qCtrl.text.trim(), _results.length, samples);
    if (!mounted) return;
    setState(() => _aiBusy = false);
    if (r == null || r['error'] != null) {
      xSnack(context, r?['error'] != null ? str(r!['error']) : 'Explain failed', error: true);
      return;
    }
    showDialog(context: context, builder: (_) => AlertDialog(
      title: const Text('AI Explanation'),
      content: SingleChildScrollView(child: Text(str(r['explanation']))),
      actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close'))],
    ));
  }

  Future<void> _buildDetectionRule() async {
    if (_qCtrl.text.trim().isEmpty) return;
    setState(() => _aiBusy = true);
    final samples = _results.take(10).map((l) => str((l as Map)['message'] ?? l['raw'])).toList();
    final r = await widget.api.buildDetection('sigma', _qCtrl.text.trim(), 'Detection from log search', samples);
    if (!mounted) return;
    setState(() => _aiBusy = false);
    if (r == null || r['error'] != null) {
      xSnack(context, r?['error'] != null ? str(r!['error']) : 'Failed', error: true);
      return;
    }
    showDialog(context: context, builder: (_) => AlertDialog(
      title: const Text('Generated Sigma Rule'),
      content: SingleChildScrollView(child: SelectableText(str(r['rule']), style: const TextStyle(fontFamily: 'monospace', fontSize: 12))),
      actions: [
        TextButton(onPressed: () => copyToClipboard(context, str(r['rule'])), child: const Text('Copy')),
        TextButton(onPressed: () => Navigator.pop(context), child: const Text('Close')),
      ],
    ));
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 6),
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
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12),
        child: Row(children: [
          TextButton.icon(
            onPressed: _aiBusy ? null : _askAI,
            icon: const Icon(Icons.psychology_outlined, size: 15),
            label: const Text('Ask AI', style: TextStyle(fontSize: 12))),
          TextButton.icon(
            onPressed: (_aiBusy || _results.isEmpty) ? null : _explainResults,
            icon: const Icon(Icons.auto_awesome_outlined, size: 15),
            label: const Text('Explain Results', style: TextStyle(fontSize: 12))),
          TextButton.icon(
            onPressed: (_aiBusy || _qCtrl.text.trim().isEmpty) ? null : _buildDetectionRule,
            icon: const Icon(Icons.rule_outlined, size: 15),
            label: const Text('Build Rule', style: TextStyle(fontSize: 12))),
          if (_aiBusy) const Padding(padding: EdgeInsets.only(left: 8), child: SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))),
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

// ── ES Query ─────────────────────────────────────────────────────────────────
// Mobile-appropriate cut of the desktop ES Query workbench (index picker +
// raw DSL editor + AI Explain + run), not a full syntax-highlighting IDE —
// see the desktop /elastic-query page for the full-featured version.

class EsQueryScreen extends StatefulWidget {
  final DashboardApi api;
  const EsQueryScreen({super.key, required this.api});
  @override State<EsQueryScreen> createState() => _EsQueryState();
}

class _EsQueryState extends State<EsQueryScreen> {
  final _dslCtrl = TextEditingController(
    text: '{\n  "query": { "match_all": {} },\n  "size": 20\n}');

  List<Map<String,dynamic>> _indices = [];
  String? _index;
  Map<String,dynamic>? _health;
  Map<String,dynamic>? _result;
  Map<String,dynamic>? _explain;
  String _error = '';
  bool _loadingMeta = true;
  bool _running     = false;
  bool _explaining  = false;

  @override void initState() { super.initState(); _loadMeta(); }
  @override void dispose() { _dslCtrl.dispose(); super.dispose(); }

  Future<void> _loadMeta() async {
    setState(() => _loadingMeta = true);
    final health  = await widget.api.esHealth();
    final indices = (await widget.api.esIndices()).cast<Map<String,dynamic>>();
    if (!mounted) return;
    setState(() {
      _health  = health;
      _indices = indices;
      if (_index == null && indices.isNotEmpty) {
        final preferred = indices.firstWhere(
          (i) => str(i['index']).startsWith('xcloak-logs-'),
          orElse: () => indices.first);
        _index = str(preferred['index']);
      }
      _loadingMeta = false;
    });
  }

  Map<String,dynamic>? _parsedDsl() {
    try { return jsonDecode(_dslCtrl.text) as Map<String,dynamic>; } catch (_) { return null; }
  }

  Future<void> _run() async {
    final dsl = _parsedDsl();
    if (dsl == null) { setState(() => _error = 'Invalid JSON — fix DSL syntax'); return; }
    setState(() { _running = true; _error = ''; _result = null; });
    final r = await widget.api.esQuery(_index ?? '', dsl);
    if (!mounted) return;
    setState(() {
      _running = false;
      if (r == null) { _error = 'Query failed'; }
      else if (r['error'] != null) { _error = str(r['error']); }
      else { _result = r; }
    });
  }

  Future<void> _runExplain() async {
    final dsl = _parsedDsl();
    if (dsl == null) { setState(() => _error = 'Invalid JSON — fix DSL syntax'); return; }
    setState(() { _explaining = true; _explain = null; });
    final r = await widget.api.esExplain(_index ?? '', dsl);
    if (!mounted) return;
    setState(() => _explaining = false);
    if (r != null && r['error'] == null) setState(() => _explain = r);
    else if (mounted) xSnack(context, r?['error'] != null ? str(r!['error']) : 'Explain failed', error: true);
  }

  @override
  Widget build(BuildContext context) {
    if (_loadingMeta) return xLoading();
    final cs = Theme.of(context).colorScheme;
    final enabled = str(_health?['status']) != 'not_configured';
    final hitsObj = _result?['hits'] as Map<String,dynamic>?;
    final hits    = (hitsObj?['hits'] as List?) ?? [];
    final total   = _result?['total'] ?? (hitsObj?['total'] as Map?)?['value'] ?? 0;

    return RefreshIndicator(
      onRefresh: _loadMeta,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Row(children: [
            Icon(enabled ? Icons.check_circle : Icons.error_outline, size: 14,
              color: enabled ? const Color(0xFF22C55E) : Colors.grey),
            const SizedBox(width: 6),
            Expanded(child: Text(
              enabled ? 'Elasticsearch connected' : 'Elasticsearch not configured on this server',
              style: TextStyle(fontSize: 12, color: enabled ? const Color(0xFF22C55E) : Colors.grey))),
          ]),
          const SizedBox(height: 12),
          if (_indices.isEmpty)
            const XEmptyState('No indices available', icon: Icons.dns_outlined)
          else
            DropdownButtonFormField<String>(
              initialValue: _indices.any((i) => str(i['index']) == _index) ? _index : null,
              decoration: const InputDecoration(labelText: 'Index', isDense: true),
              items: _indices.map((i) => DropdownMenuItem(
                value: str(i['index']),
                child: Text('${str(i['index'])}  (${str(i['docs_count'], '0')} docs)',
                  overflow: TextOverflow.ellipsis))).toList(),
              onChanged: (v) => setState(() => _index = v),
            ),
          const SizedBox(height: 14),
          SectionTitle('Query DSL'),
          TextField(
            controller: _dslCtrl,
            maxLines: 10,
            minLines: 6,
            style: const TextStyle(fontSize: 12, fontFamily: 'monospace'),
            decoration: InputDecoration(
              filled: true, fillColor: cs.surfaceContainerLow,
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
            ),
          ),
          const SizedBox(height: 10),
          Row(children: [
            Expanded(child: FilledButton.icon(
              onPressed: _running ? null : _run,
              icon: _running
                ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.play_arrow, size: 16),
              label: Text(_running ? 'Running…' : 'Run Query'),
            )),
            const SizedBox(width: 8),
            OutlinedButton.icon(
              onPressed: _explaining ? null : _runExplain,
              icon: _explaining
                ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
                : const Icon(Icons.psychology_outlined, size: 16),
              label: const Text('AI Explain'),
            ),
          ]),
          if (_error.isNotEmpty) ...[
            const SizedBox(height: 10),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(10),
              decoration: BoxDecoration(
                color: const Color(0xFFEF4444).withValues(alpha: .08),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0xFFEF4444).withValues(alpha: .3))),
              child: Text(_error, style: const TextStyle(fontSize: 12, color: Color(0xFFEF4444))),
            ),
          ],
          if (_explain != null) ...[
            const SizedBox(height: 14),
            SectionTitle('AI Explanation'),
            Container(
              width: double.infinity,
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: cs.surfaceContainerLow, borderRadius: BorderRadius.circular(10)),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                if (str(_explain!['execution_plan'], '').isNotEmpty)
                  InfoPair('Execution', str(_explain!['execution_plan'])),
                if (str(_explain!['scoring'], '').isNotEmpty)
                  InfoPair('Scoring', str(_explain!['scoring'])),
                if (str(_explain!['analyzer'], '').isNotEmpty)
                  InfoPair('Analyzer', str(_explain!['analyzer'])),
                if (_explain!['optimizations'] is List && (_explain!['optimizations'] as List).isNotEmpty) ...[
                  const SizedBox(height: 4),
                  const Text('Optimizations', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Colors.grey)),
                  const SizedBox(height: 4),
                  ...(_explain!['optimizations'] as List).map((o) => Padding(
                    padding: const EdgeInsets.only(bottom: 4),
                    child: Text('• $o', style: const TextStyle(fontSize: 12)),
                  )),
                ],
              ]),
            ),
          ],
          if (_result != null) ...[
            const SizedBox(height: 14),
            SectionTitle('Results',
              trailing: Text('$total hits · ${_result!['took'] ?? 0}ms',
                style: const TextStyle(fontSize: 11, color: Colors.grey))),
            if (hits.isEmpty)
              const XEmptyState('No hits', icon: Icons.search_off)
            else
              ...hits.map((h) {
                final hit    = h as Map<String,dynamic>;
                final source = (hit['_source'] as Map<String,dynamic>?) ?? {};
                final pretty = const JsonEncoder.withIndent('  ').convert(source);
                return Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: cs.surfaceContainerLow,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(color: cs.outlineVariant)),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Row(children: [
                      Expanded(child: Text(str(hit['_id']),
                        style: const TextStyle(fontSize: 10.5, color: Colors.grey, fontFamily: 'monospace'))),
                      IconButton(
                        icon: const Icon(Icons.copy, size: 14),
                        padding: EdgeInsets.zero, constraints: const BoxConstraints(),
                        onPressed: () => copyToClipboard(context, pretty)),
                    ]),
                    const SizedBox(height: 4),
                    Text(pretty,
                      style: const TextStyle(fontSize: 11, fontFamily: 'monospace'),
                      maxLines: 8, overflow: TextOverflow.ellipsis),
                  ]),
                );
              }),
          ],
          const SizedBox(height: 40),
        ],
      ),
    );
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
            // models.LogSource: source_type ("syslog"|"http"), ip_address,
            // enabled (bool) — there is no port/status/host field.
            final s = _sources[i] as Map<String,dynamic>;
            final id      = s['id'] as int? ?? 0;
            final enabled = s['enabled'] == true;
            return Card(child: ListTile(
              leading: Icon(Icons.source, color: enabled ? const Color(0xFF22C55E) : Colors.grey),
              title: Text(str(s['name'])),
              subtitle: Text('${str(s['source_type'])}  ·  ${str(s['ip_address'], 'any')}  ·  ${str(s['event_count'], '0')} events'),
              trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                Switch(
                  value: enabled,
                  onChanged: (v) async {
                    await widget.api.updateLogSource(id, {'enabled': v});
                    _load();
                  },
                ),
                IconButton(
                  icon: const Icon(Icons.delete_outline, color: Colors.red),
                  onPressed: () async {
                    if (await xConfirm(context, 'Delete Source', 'Delete this log source?')) { await widget.api.deleteLogSource(id); _load(); }
                  },
                ),
              ]),
            ));
          },
        ),
      ),
      floatingActionButton: FloatingActionButton(onPressed: _create, child: const Icon(Icons.add)),
    );
  }

  void _create() {
    final nameCtrl = TextEditingController();
    final ipCtrl   = TextEditingController();
    // CreateLogSource only accepts source_type "syslog" | "http" — an
    // earlier version sent an arbitrary type/host/port/protocol shape the
    // handler doesn't recognize at all, so every create attempt 400'd.
    String type = 'syslog';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Log Source'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['syslog','http'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xField(ipCtrl, 'Source IP (blank = any, syslog only)'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createLogSource({
                'name': nameCtrl.text.trim(),
                'source_type': type,
                'ip_address': ipCtrl.text.trim(),
              });
              if (context.mounted) xSnack(context, ok ? 'Log source created' : 'Failed', error: !ok);
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
            subtitle: Text('${str(r['status'])}  ·  ${r['hit_count'] ?? 0} hits  ·  ${timeAgo(r['started_at'] ?? r['created_at'])}'),
            trailing: (r['hit_count'] as int? ?? 0) > 0
                ? const Icon(Icons.warning, color: Colors.orange)
                : null,
          ));
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

class _DeceptionState extends State<DeceptionScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _traps   = [];
  List _canaries = [];
  List _trips    = [];
  bool _loading  = true;
  bool _loadingCanaries = true;

  @override void initState() {
    super.initState();
    _tabs = TabController(length: 2, vsync: this);
    _tabs.addListener(() { if (!_tabs.indexIsChanging && _tabs.index == 1) _loadCanaries(); });
    _load();
  }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.get('/api/honeyports');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['honeyports'] ?? []) : []);
    setState(() { _traps = list as List; _loading = false; });
  }

  Future<void> _loadCanaries() async {
    setState(() => _loadingCanaries = true);
    final res = await Future.wait([widget.api.canaryTokens(), widget.api.canaryTrips()]);
    if (!mounted) return;
    setState(() { _canaries = res[0]; _trips = res[1]; _loadingCanaries = false; });
  }

  void _createCanary() {
    final nameCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    final deployCtrl = TextEditingController();
    String type = 'file';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Canary Token'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['file','url','dns','aws_key'], (v) => ss(() => type = v!)),
          const SizedBox(height: 10),
          xField(deployCtrl, 'Deployed To (host/path)'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createCanary({
                'token_type': type, 'name': nameCtrl.text.trim(),
                'description': descCtrl.text.trim(), 'deployed_to': deployCtrl.text.trim(),
              });
              if (context.mounted) xSnack(context, ok ? 'Canary created' : 'Failed', error: !ok);
              _loadCanaries();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  void _createTrap() {
    final agentCtrl = TextEditingController();
    final portCtrl  = TextEditingController();
    final descCtrl  = TextEditingController();
    String protocol = 'tcp', severity = 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Honeypot'),
          xField(agentCtrl, 'Agent ID', keyboardType: TextInputType.number),
          const SizedBox(height: 10),
          xField(portCtrl, 'Port', keyboardType: TextInputType.number),
          const SizedBox(height: 10),
          xDropdown('Protocol', protocol, ['tcp','udp'], (v) => ss(() => protocol = v!)),
          const SizedBox(height: 10),
          xDropdown('Alert Severity', severity, ['critical','high','medium','low'], (v) => ss(() => severity = v!)),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              final agentId = int.tryParse(agentCtrl.text.trim());
              final port    = int.tryParse(portCtrl.text.trim());
              if (agentId == null || port == null) { xSnack(ctx, 'Agent ID and Port must be numbers', error: true); return; }
              Navigator.pop(ctx);
              await widget.api.createHoneyport({
                'agent_id': agentId, 'port': port, 'protocol': protocol,
                'description': descCtrl.text.trim(), 'alert_severity': severity,
              });
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  Widget _honeypotsTab() => Scaffold(
    body: _loading ? xLoading() : _traps.isEmpty
      ? const XEmptyState('No deception traps configured', icon: Icons.pest_control)
      : RefreshIndicator(
          onRefresh: _load,
          child: ListView.builder(
            padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
            itemCount: _traps.length,
            itemBuilder: (_, i) {
              final t = _traps[i] as Map<String,dynamic>;
              final id     = t['id'] as int? ?? 0;
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
                  // No toggle endpoint exists on the backend — a honeypot
                  // is either live or gone, so "disable" means delete.
                  trailing: IconButton(
                    icon: const Icon(Icons.delete_outline, color: Colors.redAccent),
                    tooltip: 'Delete honeypot',
                    onPressed: () async {
                      if (!await xConfirm(context, 'Delete Honeypot', 'Stop and remove this trap?')) return;
                      await widget.api.deleteHoneyport(id);
                      _load();
                    },
                  ),
                ),
              );
            },
          ),
        ),
    floatingActionButton: FloatingActionButton(onPressed: _createTrap, child: const Icon(Icons.add)),
  );

  Widget _canaryTab() => Scaffold(
    body: _loadingCanaries ? xLoading() : ListView(
      padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
      children: [
        SectionTitle('Canary Tokens  (${_canaries.length})'),
        if (_canaries.isEmpty)
          const Padding(padding: EdgeInsets.all(16),
            child: Center(child: Text('No canary tokens', style: TextStyle(color: Colors.grey))))
        else
          ..._canaries.map((c) {
            final tok    = c as Map<String,dynamic>;
            final id     = tok['id'] as int? ?? 0;
            final active = tok['is_active'] == true;
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: Icon(Icons.egg_outlined, color: active ? const Color(0xFFF59E0B) : Colors.grey),
                title: Text(str(tok['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('${str(tok['token_type'])}  ·  ${str(tok['deployed_to'], '—')}  ·  '
                  '${tok['trip_count'] ?? 0} trips'),
                trailing: PopupMenuButton<String>(
                  onSelected: (v) async {
                    if (v == 'toggle') { await widget.api.toggleCanary(id); _loadCanaries(); }
                    if (v == 'delete') {
                      if (await xConfirm(context, 'Delete Canary', 'Delete this canary token?')) {
                        await widget.api.deleteCanary(id);
                        _loadCanaries();
                      }
                    }
                  },
                  itemBuilder: (_) => [
                    PopupMenuItem(value: 'toggle', child: Text(active ? 'Disable' : 'Enable')),
                    const PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                  ],
                ),
              ),
            );
          }),
        const SizedBox(height: 16),
        SectionTitle('Trips  (${_trips.length})'),
        if (_trips.isEmpty)
          const Padding(padding: EdgeInsets.all(16),
            child: Center(child: Text('No canary trips recorded', style: TextStyle(color: Colors.grey))))
        else
          ..._trips.map((t) {
            // CanaryTrip only carries token_id — resolve the name from the
            // already-loaded token list rather than guessing a name field.
            final trip = t as Map<String,dynamic>;
            final tokenId = trip['token_id'];
            final token = _canaries.cast<Map<String,dynamic>>().firstWhere(
              (c) => c['id'] == tokenId, orElse: () => const {});
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.warning_amber, color: Color(0xFFEF4444)),
                title: Text(str(token['name'], 'Canary #$tokenId'),
                  style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13)),
                subtitle: Text('${str(trip['source_ip'], '—')}  ·  ${timeAgo(trip['tripped_at'])}'),
              ),
            );
          }),
      ],
    ),
    floatingActionButton: FloatingActionButton(onPressed: _createCanary, child: const Icon(Icons.add)),
  );

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, tabs: const [Tab(text: 'Honeypots'), Tab(text: 'Canary Tokens')]),
      Expanded(child: TabBarView(controller: _tabs, children: [_honeypotsTab(), _canaryTab()])),
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
  Map  _summary   = {};
  List _baselines = [];
  List _findings  = [];
  bool _loading   = true;

  @override void initState() { super.initState(); _load(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final bRes = await widget.api.get('/api/threat/baselines');
    // GetAnomaliesHandler returns a bare array of AnomalyFinding.
    final aRes = await widget.api.get('/api/ai/anomalies');
    if (!mounted) return;
    final baselines = bRes is List ? bRes : (bRes is Map ? (bRes['baselines'] ?? bRes['data'] ?? []) : []);
    final findings  = aRes is List ? aRes : (aRes is Map ? (aRes['findings'] ?? aRes['data'] ?? []) : []);
    final s = <String,dynamic>{
      'anomalies_today': (findings as List).length,
      'active_models': baselines is List ? baselines.length : 0,
    };
    setState(() { _summary = s; _baselines = baselines as List; _findings = findings; _loading = false; });
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
              padding: EdgeInsets.all(16),
              child: Center(child: Text('No behavioral baselines yet',
                style: TextStyle(color: Colors.grey))),
            ),
          const SizedBox(height: 16),
          SectionTitle('Anomaly Findings'),
          if (_findings.isEmpty)
            const Padding(
              padding: EdgeInsets.all(16),
              child: Center(child: Text('No anomaly findings',
                style: TextStyle(color: Colors.grey))),
            )
          else
            ..._findings.map((f) {
              final finding = f as Map<String,dynamic>;
              final id  = finding['id'] as int? ?? 0;
              final ack = finding['acknowledged'] == true;
              return Card(
                margin: const EdgeInsets.only(bottom: 8),
                child: ListTile(
                  leading: SevChip(str(finding['severity'])),
                  title: Text(str(finding['finding_type'], 'Anomaly'),
                    style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13.5)),
                  subtitle: Text(str(finding['description'], ''),
                    maxLines: 2, overflow: TextOverflow.ellipsis, style: const TextStyle(fontSize: 12)),
                  trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                    Text('${finding['score'] ?? '-'}',
                      style: const TextStyle(fontWeight: FontWeight.w800, fontSize: 15)),
                    if (!ack)
                      IconButton(
                        icon: const Icon(Icons.check_circle_outline, size: 18),
                        onPressed: () async {
                          final ok = await widget.api.ackThreatFinding(id);
                          if (context.mounted) xSnack(context, ok ? 'Acknowledged' : 'Failed', error: !ok);
                          _load();
                        },
                      ),
                  ]),
                ),
              );
            }),
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

  void _addToIoc(Map<String,dynamic> log) {
    final valCtrl = TextEditingController(text: str(log['log_message']));
    String type = 'ip';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('Add to IOCs'),
          xField(valCtrl, 'Indicator value'),
          const SizedBox(height: 10),
          xDropdown('Type', type, ['ip','domain','hash','url','email'], (v) => ss(() => type = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createIoc({'type': type, 'value': valCtrl.text.trim(), 'severity': 'high', 'description': 'From live log'});
              if (context.mounted) xSnack(context, ok ? 'IOC created' : 'Failed', error: !ok);
            },
            child: const Text('Create IOC'),
          )),
        ]),
      )),
    );
  }

  // models.Log has no level/severity field — the raw syslog/log_message text
  // sometimes embeds one (e.g. "kernel: [UFW BLOCK]") but there's no
  // structured field to color-code by, so the source tag is shown instead
  // of a fabricated severity color.
  Color _sourceColor(String source) => switch (source.toLowerCase()) {
    'syslog' => const Color(0xFF3B82F6),
    'http'   => const Color(0xFF8B5CF6),
    _        => Colors.grey,
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
            // models.Log — log_message/log_source/agent_id/collected_at,
            // not message/level/source/host/timestamp (those belonged to a
            // different, unrelated shape and always rendered as em-dashes).
            final log = _logs[i] as Map<String,dynamic>;
            final source = str(log['log_source'], 'log');
            return InkWell(
              onLongPress: () => _addToIoc(log),
              child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
              decoration: BoxDecoration(
                border: Border(bottom: BorderSide(color: Colors.grey.withValues(alpha: .08)))),
              child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(source.toUpperCase().padRight(6),
                  style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800,
                    color: _sourceColor(source), fontFamily: 'monospace')),
                const SizedBox(width: 8),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(str(log['log_message']),
                    style: const TextStyle(fontSize: 12, fontFamily: 'monospace')),
                  Text('Agent ${str(log['agent_id'], '—')}',
                    style: const TextStyle(fontSize: 10, color: Colors.grey)),
                ])),
                Text(timeAgo(log['collected_at']),
                  style: const TextStyle(fontSize: 10, color: Colors.grey)),
                IconButton(
                  icon: const Icon(Icons.flag_outlined, size: 15),
                  padding: EdgeInsets.zero, constraints: const BoxConstraints(),
                  tooltip: 'Add to IOCs',
                  onPressed: () => _addToIoc(log),
                ),
              ]),
              ),
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
    final r = await widget.api.vmFindings(severity: _sevFilter);
    if (!mounted) return;
    setState(() { _vulns = r; _loading = false; });
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
                // vm_findings — cve_id/cvss_score/severity/detected_at are
                // real; asset_name/kev_listed/exploit_available are new
                // signal the old priority-queue endpoint didn't carry.
                final v = _vulns[i] as Map<String,dynamic>;
                final id = v['id'] as int? ?? 0;
                final cvss = v['cvss_score'] ?? 0.0;
                final sev  = str(v['severity']);
                final kev  = v['kev_listed'] == true;
                final status = str(v['status'], 'open');
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: SevChip(sev),
                    title: Row(children: [
                      Expanded(child: Text(str(v['cve_id']),
                        style: const TextStyle(fontWeight: FontWeight.w800, fontFamily: 'monospace'))),
                      if (kev) Container(
                        margin: const EdgeInsets.only(left: 6),
                        padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                        decoration: BoxDecoration(color: const Color(0xFFEF4444).withValues(alpha: .15), borderRadius: BorderRadius.circular(6)),
                        child: const Text('KEV', style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w800, color: Color(0xFFEF4444)))),
                    ]),
                    subtitle: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Text('${str(v['vendor'], '')} ${str(v['product'], '')}  ·  ${str(v['asset_name'], '')}',
                        maxLines: 2, overflow: TextOverflow.ellipsis,
                        style: const TextStyle(fontSize: 12)),
                      const SizedBox(height: 2),
                      Text('CVSS: $cvss  ·  $status  ·  ${timeAgo(v['detected_at'])}',
                        style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    ]),
                    trailing: status == 'open' ? PopupMenuButton<String>(
                      child: SevChip(sev),
                      onSelected: (action) async {
                        final ok = await widget.api.vmFindingAction(id, action);
                        if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                        _load();
                      },
                      itemBuilder: (_) => const [
                        PopupMenuItem(value: 'mark_patched', child: Text('Mark Patched')),
                        PopupMenuItem(value: 'accept_risk', child: Text('Accept Risk')),
                        PopupMenuItem(value: 'defer', child: Text('Defer')),
                      ],
                    ) : StatusChip(status),
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

class _FirewallState extends State<FirewallScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _rules     = [];
  List _zones     = [];
  List _nat       = [];
  List _policies  = [];
  List _approvals = [];
  bool _loading   = true;
  bool _loadingOthers = true;
  final _loadedTabs = <int>{0};

  @override void initState() {
    super.initState();
    _tabs = TabController(length: 5, vsync: this);
    _tabs.addListener(() { if (!_tabs.indexIsChanging) _loadTab(_tabs.index); });
    _load();
  }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _loadTab(int i) async {
    if (_loadedTabs.contains(i)) return;
    _loadedTabs.add(i);
    setState(() => _loadingOthers = true);
    switch (i) {
      case 1: _zones = await widget.api.fweZones(); break;
      case 2: _nat = await widget.api.fweNAT(); break;
      case 3: _policies = await widget.api.fwePolicies(); break;
      case 4: _approvals = await widget.api.fweApprovals(); break;
    }
    if (!mounted) return;
    setState(() => _loadingOthers = false);
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.get('/api/firewall/rules');
    if (!mounted) return;
    final list = r is List ? r : (r is Map ? (r['data'] ?? r['rules'] ?? []) : []);
    setState(() { _rules = list as List; _loading = false; });
  }

  void _createZone() {
    final nameCtrl = TextEditingController();
    String zoneType = 'custom', trust = 'medium';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Zone'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', zoneType, ['trusted','untrusted','dmz','custom'], (v) => ss(() => zoneType = v!)),
          const SizedBox(height: 10),
          xDropdown('Trust Level', trust, ['high','medium','low','none'], (v) => ss(() => trust = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createFweZone({'name': nameCtrl.text.trim(), 'zone_type': zoneType, 'trust_level': trust});
              if (context.mounted) xSnack(context, ok ? 'Zone created' : 'Failed', error: !ok);
              setState(() => _loadedTabs.remove(1));
              _loadTab(1);
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  void _createNAT() {
    final nameCtrl = TextEditingController();
    final srcCtrl  = TextEditingController();
    final transCtrl = TextEditingController();
    String natType = 'snat';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New NAT Rule'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xDropdown('Type', natType, ['snat','dnat','masquerade'], (v) => ss(() => natType = v!)),
          const SizedBox(height: 10),
          xField(srcCtrl, 'Source IP'),
          const SizedBox(height: 10),
          xField(transCtrl, 'Translated IP'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createFweNAT({'name': nameCtrl.text.trim(), 'nat_type': natType, 'src_ip': srcCtrl.text.trim(), 'translated_ip': transCtrl.text.trim()});
              if (context.mounted) xSnack(context, ok ? 'NAT rule created' : 'Failed', error: !ok);
              setState(() => _loadedTabs.remove(2));
              _loadTab(2);
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  void _createPolicy() {
    final nameCtrl = TextEditingController();
    final ownerCtrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Policy'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(ownerCtrl, 'Owner'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createFwePolicy({'name': nameCtrl.text.trim(), 'owner': ownerCtrl.text.trim()});
              if (context.mounted) xSnack(context, ok ? 'Policy created' : 'Failed', error: !ok);
              setState(() => _loadedTabs.remove(3));
              _loadTab(3);
            },
            child: const Text('Create'),
          )),
        ]),
      ),
    );
  }

  Color _actionColor(String action) => switch (action.toLowerCase()) {
    'block' || 'deny' || 'drop' => const Color(0xFFEF4444),
    'allow' || 'accept'         => const Color(0xFF22C55E),
    _                           => const Color(0xFFF59E0B),
  };

  void _createRule() {
    final nameCtrl = TextEditingController();
    final srcCtrl  = TextEditingController(text: '*');
    final dstCtrl  = TextEditingController(text: '*');
    final portCtrl = TextEditingController();
    String action = 'block', protocol = 'tcp';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Firewall Rule'),
          xField(nameCtrl, 'Name'),
          const SizedBox(height: 10),
          xField(srcCtrl, 'Source IP (or *)'),
          const SizedBox(height: 10),
          xField(dstCtrl, 'Destination IP (or *)'),
          const SizedBox(height: 10),
          xField(portCtrl, 'Port / Range (e.g. 443 or 8000-9000)'),
          const SizedBox(height: 10),
          xDropdown('Protocol', protocol, ['tcp','udp','icmp','any'], (v) => ss(() => protocol = v!)),
          const SizedBox(height: 10),
          xDropdown('Action', action, ['block','allow'], (v) => ss(() => action = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              if (nameCtrl.text.trim().isEmpty) { xSnack(ctx, 'Name is required', error: true); return; }
              Navigator.pop(ctx);
              await widget.api.createFirewallRule({
                'name': nameCtrl.text.trim(),
                'source_ip': srcCtrl.text.trim(),
                'destination_ip': dstCtrl.text.trim(),
                'port_range': portCtrl.text.trim(),
                'protocol': protocol,
                'action': action,
                'direction': 'in',
                'enabled': true,
              });
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  Widget _rulesTab() => Scaffold(
    floatingActionButton: FloatingActionButton(
      onPressed: _createRule,
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
                      color: _actionColor(action).withValues(alpha: .12),
                      borderRadius: BorderRadius.circular(8)),
                    child: Icon(
                      action.toLowerCase() == 'block' || action.toLowerCase() == 'deny'
                        ? Icons.block : Icons.check_circle_outline,
                      color: _actionColor(action), size: 20),
                  ),
                  title: Text(str(rule['name'] ?? rule['description'] ?? 'Rule ${rule['id']}'),
                    style: const TextStyle(fontWeight: FontWeight.w700)),
                  subtitle: Text(
                    '${str(rule['source_ip'] ?? '*')} → '
                    '${str(rule['destination_ip'] ?? '*')}  '
                    'Port: ${str(rule['port_range'] ?? '').isNotEmpty ? rule['port_range'] : (rule['port'] ?? '*')}',
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

  Widget _zonesTab() => Scaffold(
    floatingActionButton: FloatingActionButton(onPressed: _createZone, child: const Icon(Icons.add)),
    body: _loadingOthers ? xLoading() : _zones.isEmpty
      ? const XEmptyState('No zones configured', icon: Icons.shield_outlined)
      : ListView.builder(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
          itemCount: _zones.length,
          itemBuilder: (_, i) {
            final z = _zones[i] as Map<String,dynamic>;
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: Icon(z['enabled'] == true ? Icons.shield : Icons.shield_outlined,
                  color: z['enabled'] == true ? const Color(0xFF3B82F6) : Colors.grey),
                title: Text(str(z['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('${str(z['zone_type'])}  ·  trust: ${str(z['trust_level'])}', style: const TextStyle(fontSize: 11.5)),
              ),
            );
          },
        ),
  );

  Widget _natTab() => Scaffold(
    floatingActionButton: FloatingActionButton(onPressed: _createNAT, child: const Icon(Icons.add)),
    body: _loadingOthers ? xLoading() : _nat.isEmpty
      ? const XEmptyState('No NAT rules configured', icon: Icons.swap_horiz)
      : ListView.builder(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
          itemCount: _nat.length,
          itemBuilder: (_, i) {
            final n = _nat[i] as Map<String,dynamic>;
            final id = n['id'] as int? ?? 0;
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.swap_horiz, color: Color(0xFF8B5CF6)),
                title: Text(str(n['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('${str(n['nat_type'])}  ·  ${n['hit_count'] ?? 0} hits', style: const TextStyle(fontSize: 11.5)),
                trailing: IconButton(
                  icon: const Icon(Icons.delete_outline, color: Colors.redAccent, size: 18),
                  onPressed: () async {
                    if (!await xConfirm(context, 'Delete NAT Rule', 'Delete this NAT rule?')) return;
                    await widget.api.deleteFweNAT(id);
                    setState(() => _loadedTabs.remove(2));
                    _loadTab(2);
                  },
                ),
              ),
            );
          },
        ),
  );

  Widget _policiesTab() => Scaffold(
    floatingActionButton: FloatingActionButton(onPressed: _createPolicy, child: const Icon(Icons.add)),
    body: _loadingOthers ? xLoading() : _policies.isEmpty
      ? const XEmptyState('No policies configured', icon: Icons.policy_outlined)
      : ListView.builder(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
          itemCount: _policies.length,
          itemBuilder: (_, i) {
            final p = _policies[i] as Map<String,dynamic>;
            final id = p['id'] as int? ?? 0;
            final status = str(p['status'], 'active');
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: const Icon(Icons.policy_outlined, color: Color(0xFFF59E0B)),
                title: Text(str(p['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('${str(p['policy_id'])}  ·  priority ${str(p['priority'])}  ·  ${p['rule_count'] ?? 0} rules  ·  ${str(p['owner'], '—')}',
                  style: const TextStyle(fontSize: 11)),
                trailing: PopupMenuButton<String>(
                  child: StatusChip(status),
                  onSelected: (v) async {
                    if (v == 'delete') {
                      if (!await xConfirm(context, 'Delete Policy', 'Delete this policy?')) return;
                      await widget.api.deleteFwePolicy(id);
                    } else {
                      await widget.api.updateFwePolicy(id, {'status': v});
                    }
                    setState(() => _loadedTabs.remove(3));
                    _loadTab(3);
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(value: 'active', child: Text('Set Active')),
                    PopupMenuItem(value: 'disabled', child: Text('Disable')),
                    PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
                  ],
                ),
              ),
            );
          },
        ),
  );

  Widget _approvalsTab() => _loadingOthers ? xLoading() : _approvals.isEmpty
    ? const XEmptyState('No pending approvals', icon: Icons.rule_folder_outlined)
    : ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: _approvals.length,
        itemBuilder: (_, i) {
          final a = _approvals[i] as Map<String,dynamic>;
          final id = a['id'] as int? ?? 0;
          final status = str(a['status'], 'pending');
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: Padding(
              padding: const EdgeInsets.all(12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(child: Text(str(a['change_type']), style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 13))),
                  StatusChip(status),
                ]),
                const SizedBox(height: 4),
                Text(str(a['description']), style: const TextStyle(fontSize: 12, color: Colors.grey)),
                const SizedBox(height: 4),
                Text('Requested by ${str(a['requester'])}  ·  ${timeAgo(a['created_at'])}',
                  style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                if (status == 'pending') ...[
                  const SizedBox(height: 8),
                  Row(children: [
                    Expanded(child: OutlinedButton(
                      onPressed: () async {
                        await widget.api.decideFweApproval(id, 'rejected');
                        setState(() => _loadedTabs.remove(4));
                        _loadTab(4);
                      },
                      child: const Text('Reject'))),
                    const SizedBox(width: 8),
                    Expanded(child: FilledButton(
                      onPressed: () async {
                        await widget.api.decideFweApproval(id, 'approved');
                        setState(() => _loadedTabs.remove(4));
                        _loadTab(4);
                      },
                      child: const Text('Approve'))),
                  ]),
                ],
              ]),
            ),
          );
        },
      );

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Rules'), Tab(text: 'Zones'), Tab(text: 'NAT'), Tab(text: 'Policies'), Tab(text: 'Approvals'),
      ]),
      Expanded(child: TabBarView(controller: _tabs, children: [
        _rulesTab(), _zonesTab(), _natTab(), _policiesTab(), _approvalsTab(),
      ])),
    ]);
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
    final scripts = await widget.api.scriptTemplates();
    final history = await widget.api.scriptHistory();
    if (!mounted) return;
    setState(() { _scripts = scripts; _history = history; _loading = false; });
  }

  Future<void> _run(Map<String,dynamic> script) async {
    final agents = await widget.api.agents();
    if (!mounted) return;
    if (agents.isEmpty) { xSnack(context, 'No agents available to target', error: true); return; }

    final target = await showDialog<Map<String,dynamic>>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text('Run "${str(script['label'])}" on…'),
        content: SizedBox(
          width: double.maxFinite,
          child: ListView.builder(
            shrinkWrap: true,
            itemCount: agents.length,
            itemBuilder: (_, i) {
              final a = agents[i] as Map<String,dynamic>;
              return ListTile(
                leading: const Icon(Icons.computer),
                title: Text(str(a['hostname'] ?? a['name'] ?? 'Agent ${a['id']}')),
                onTap: () => Navigator.pop(ctx, a),
              );
            },
          ),
        ),
        actions: [TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel'))],
      ),
    );
    if (target == null || !mounted) return;

    xSnack(context, 'Running ${str(script['label'])}…');
    final result = await widget.api.runScript(
      [target['id'] as int],
      str(script['script']),
      label: str(script['label']),
      shell: str(script['shell']).isEmpty ? 'bash' : str(script['shell']),
    );
    if (mounted) xSnack(context, result == null || result['error'] != null ? 'Execution failed' : 'Script dispatched', error: result == null || result['error'] != null);
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
                          color: const Color(0xFF6366F1).withValues(alpha: .1),
                          borderRadius: BorderRadius.circular(8)),
                        child: const Icon(Icons.terminal, color: Color(0xFF6366F1), size: 20),
                      ),
                      title: Text(str(s['label']),
                        style: const TextStyle(fontWeight: FontWeight.w700)),
                      subtitle: Text(str(s['category'] ?? ''),
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
                    title: Text(str(h['label']),
                      style: const TextStyle(fontWeight: FontWeight.w600)),
                    subtitle: Text('${str(h['hostname'] ?? 'unknown host')}  ·  ${timeAgo(h['created_at'])}'),
                    trailing: StatusChip(status),
                  ),
                );
              },
            )),
    ]);
  }
}
