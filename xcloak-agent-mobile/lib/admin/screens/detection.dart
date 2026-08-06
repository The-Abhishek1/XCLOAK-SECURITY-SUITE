import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// Alerts Screen — enterprise with bulk select, swipe actions, expandable cards
// ─────────────────────────────────────────────────────────────────────────────

class AlertsScreen extends StatefulWidget {
  final DashboardApi api;
  const AlertsScreen({super.key, required this.api});
  @override State<AlertsScreen> createState() => _AlertsState();
}

class _AlertsState extends State<AlertsScreen> {
  List   _alerts   = [];
  bool   _loading  = true;
  bool   _bulkMode = false;
  String _sevFilter    = '';
  String _statusFilter = 'open';
  String _query        = '';
  final Set<int>         _selected = {};
  final TextEditingController _searchCtrl = TextEditingController();

  final Map<String,int> _sevCounts = {};

  @override void initState() { super.initState(); _load(); }
  @override void dispose()   { _searchCtrl.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.alerts(sev: _sevFilter, status: _statusFilter, q: _query, per: 100);
    if (!mounted) return;
    _sevCounts.clear();
    for (final a in r) {
      final s = str((a as Map<String,dynamic>)['severity']);
      _sevCounts[s] = (_sevCounts[s] ?? 0) + 1;
    }
    setState(() { _alerts = r; _loading = false; _selected.clear(); _bulkMode = false; });
  }

  Future<void> _bulkAck() async {
    final ok = await widget.api.bulkAck(_selected.toList());
    if (mounted) xSnack(context, ok ? 'Acknowledged ${_selected.length} alerts' : 'Bulk ack failed', error: !ok);
    _load();
  }

  Future<void> _ackAlert(int id) async {
    final ok = await widget.api.ackAlert(id);
    if (mounted) xSnack(context, ok ? 'Alert acknowledged' : 'Failed', error: !ok);
    _load();
  }

  Future<void> _resolveAlert(int id) async {
    final ok = await widget.api.resolveAlert(id);
    if (mounted) xSnack(context, ok ? 'Alert resolved' : 'Failed', error: !ok);
    _load();
  }

  void _showDetail(Map<String,dynamic> alert) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => _AlertDetailSheet(alert: alert, api: widget.api, onAction: _load),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      if (_bulkMode)
        BulkBar(
          count: _selected.length,
          onCancel: () => setState(() { _bulkMode = false; _selected.clear(); }),
          actions: [
            (Icons.check_circle_outline, 'Ack All', _bulkAck),
            (Icons.select_all, 'Select All', () => setState(() {
              for (final a in _alerts) { _selected.add((a as Map)['id'] as int? ?? 0); }
            })),
          ],
        )
      else ...[
        Padding(
          padding: const EdgeInsets.fromLTRB(12, 10, 12, 0),
          child: Row(children: [
            Expanded(child: TextField(
              controller: _searchCtrl,
              decoration: InputDecoration(
                hintText: 'Search alerts…',
                hintStyle: const TextStyle(fontSize: 13),
                prefixIcon: const Icon(Icons.search, size: 18),
                suffixIcon: _query.isNotEmpty
                  ? IconButton(icon: const Icon(Icons.close, size: 14),
                      onPressed: () { setState(() { _query = ''; _searchCtrl.clear(); }); _load(); })
                  : null,
                isDense: true,
                contentPadding: const EdgeInsets.symmetric(vertical: 10),
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(12)),
              ),
              onSubmitted: (v) { setState(() => _query = v); _load(); },
            )),
            const SizedBox(width: 8),
            IconButton.filledTonal(
              onPressed: () => setState(() => _bulkMode = true),
              icon: const Icon(Icons.checklist, size: 18),
              tooltip: 'Bulk select',
              style: IconButton.styleFrom(tapTargetSize: MaterialTapTargetSize.shrinkWrap),
            ),
          ]),
        ),
        FilterRow(
          selected: _statusFilter,
          onSelect: (v) { setState(() => _statusFilter = v); _load(); },
          chips: const [
            ('Open', 'open', null),
            ('Ack\'d', 'acknowledged', null),
            ('Resolved', 'resolved', null),
            ('All', '', null),
          ],
        ),
        if (_sevCounts.isNotEmpty)
          FilterRow(
            selected: _sevFilter,
            onSelect: (v) { setState(() => _sevFilter = v); _load(); },
            chips: [
              ('All', '', _alerts.length),
              ...['critical','high','medium','low','info']
                .where((s) => (_sevCounts[s] ?? 0) > 0)
                .map((s) => (_kSevLabel(s), s, _sevCounts[s])),
            ],
          ),
      ],
      Expanded(child: _loading
        ? xLoading()
        : _alerts.isEmpty
          ? const XEmptyState('No alerts match filter', icon: Icons.notifications_none)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
                itemCount: _alerts.length,
                itemBuilder: (_, i) {
                  final alert = _alerts[i] as Map<String,dynamic>;
                  final id    = alert['id'] as int? ?? 0;
                  final card  = _AlertCard(
                    alert: alert,
                    selected: _selected.contains(id),
                    bulkMode: _bulkMode,
                    onTap: () {
                      if (_bulkMode) {
                        setState(() { _selected.contains(id) ? _selected.remove(id) : _selected.add(id); });
                      } else {
                        _showDetail(alert);
                      }
                    },
                    onLongPress: () => setState(() { _bulkMode = true; _selected.add(id); }),
                    onAck:     () => _ackAlert(id),
                    onResolve: () => _resolveAlert(id),
                  );
                  return swipeCard(
                    key: id,
                    rightLabel: 'Acknowledge',  rightColor: const Color(0xFF22C55E),
                    rightIcon:  Icons.check,
                    leftLabel:  'Resolve',      leftColor: Colors.blueGrey,
                    leftIcon:   Icons.done_all,
                    onRight: () => _ackAlert(id),
                    onLeft:  () => _resolveAlert(id),
                    child: card,
                  );
                },
              ),
            )),
    ]);
  }

  String _kSevLabel(String s) => switch (s) {
    'critical' => 'Critical', 'high' => 'High', 'medium' => 'Medium',
    'low' => 'Low', 'info' => 'Info', _ => s,
  };
}

class _AlertCard extends StatefulWidget {
  final Map<String,dynamic> alert;
  final bool selected, bulkMode;
  final VoidCallback onTap, onLongPress, onAck, onResolve;
  const _AlertCard({required this.alert, required this.selected, required this.bulkMode,
    required this.onTap, required this.onLongPress, required this.onAck, required this.onResolve});
  @override State<_AlertCard> createState() => _AlertCardState();
}

class _AlertCardState extends State<_AlertCard> {
  bool _expanded = false;

  @override
  Widget build(BuildContext context) {
    final cs  = Theme.of(context).colorScheme;
    final a   = widget.alert;
    final col = sevColor(str(a['severity']));

    return GestureDetector(
      onTap:       widget.onTap,
      onLongPress: widget.onLongPress,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(12),
          border: Border.all(
            color: widget.selected ? cs.primary : col.withValues(alpha: .28),
            width: widget.selected ? 2 : 1,
          ),
          color: widget.selected ? cs.primary.withValues(alpha: .06) : col.withValues(alpha: .03),
        ),
        clipBehavior: Clip.hardEdge,
        child: Column(children: [
          Row(children: [
            Container(width: 4, color: col),
            if (widget.bulkMode)
              Padding(
                padding: const EdgeInsets.only(left: 8),
                child: Checkbox(
                  value: widget.selected, onChanged: (_) => widget.onTap(),
                  visualDensity: VisualDensity.compact),
              ),
            Expanded(child: Padding(
              padding: const EdgeInsets.fromLTRB(10, 10, 6, 10),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Row(children: [
                  Expanded(child: Text(
                    str(a['rule_name'] ?? a['message'] ?? 'Alert'),
                    style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700),
                    maxLines: _expanded ? null : 1,
                    overflow: _expanded ? null : TextOverflow.ellipsis,
                  )),
                  SevChip(str(a['severity'])),
                  const SizedBox(width: 4),
                  GestureDetector(
                    onTap: () => setState(() => _expanded = !_expanded),
                    child: Icon(
                      _expanded ? Icons.keyboard_arrow_up : Icons.keyboard_arrow_down,
                      size: 18, color: Colors.grey),
                  ),
                ]),
                const SizedBox(height: 4),
                Row(children: [
                  if (a['hostname'] != null) ...[
                    const Icon(Icons.computer, size: 11, color: Colors.grey),
                    const SizedBox(width: 3),
                    Text(str(a['hostname']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
                    const SizedBox(width: 8),
                  ],
                  const Icon(Icons.access_time, size: 11, color: Colors.grey),
                  const SizedBox(width: 3),
                  Text(timeAgo(a['created_at']), style: const TextStyle(fontSize: 11, color: Colors.grey)),
                  if (a['status'] != null) ...[
                    const SizedBox(width: 8),
                    StatusChip(str(a['status'])),
                  ],
                ]),
              ]),
            )),
            if (!widget.bulkMode) Column(children: [
              _IconBtn(Icons.check_circle_outline, const Color(0xFF22C55E), widget.onAck, 'Ack'),
              _IconBtn(Icons.done_all, Colors.blueGrey, widget.onResolve, 'Resolve'),
            ]),
          ]),
          if (_expanded) ...[
            const Divider(height: 1),
            Padding(
              padding: const EdgeInsets.fromLTRB(14, 10, 14, 12),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                if (str(a['log_message'], '').isNotEmpty) ...[
                  Text(str(a['log_message']),
                    style: const TextStyle(fontSize: 12.5, color: Colors.grey), maxLines: 3, overflow: TextOverflow.ellipsis),
                  const SizedBox(height: 8),
                ],
                if (str(a['mitre_technique'], '').isNotEmpty || str(a['mitre_tactic'], '').isNotEmpty)
                  Wrap(spacing: 6, runSpacing: 4, children: [
                    if (str(a['mitre_technique'], '').isNotEmpty) _MitreTag(str(a['mitre_technique'])),
                    if (str(a['mitre_tactic'], '').isNotEmpty) _MitreTag(str(a['mitre_tactic'])),
                  ]),
                const SizedBox(height: 8),
                if (str(a['hostname'], '').isNotEmpty) InfoPair('Hostname', str(a['hostname'])),
                if (str(a['fingerprint'], '').isNotEmpty) InfoPair('Fingerprint', str(a['fingerprint'])),
              ]),
            ),
          ],
        ]),
      ),
    );
  }
}

class _IconBtn extends StatelessWidget {
  final IconData icon; final Color color; final VoidCallback onTap; final String tooltip;
  const _IconBtn(this.icon, this.color, this.onTap, this.tooltip);
  @override
  Widget build(BuildContext context) => Tooltip(
    message: tooltip,
    child: InkWell(onTap: onTap, child: Padding(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 8),
      child: Icon(icon, size: 19, color: color),
    )),
  );
}

class _MitreTag extends StatelessWidget {
  final String label;
  const _MitreTag(this.label);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
    decoration: BoxDecoration(
      color: const Color(0xFF6366F1).withValues(alpha: .1),
      borderRadius: BorderRadius.circular(6),
      border: Border.all(color: const Color(0xFF6366F1).withValues(alpha: .25))),
    child: Text(label, style: const TextStyle(fontSize: 10.5,
      color: Color(0xFF6366F1), fontWeight: FontWeight.w700)),
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert detail bottom sheet
// ─────────────────────────────────────────────────────────────────────────────

class _AlertDetailSheet extends StatefulWidget {
  final Map<String,dynamic> alert;
  final DashboardApi api;
  final VoidCallback onAction;
  const _AlertDetailSheet({required this.alert, required this.api, required this.onAction});
  @override State<_AlertDetailSheet> createState() => _AlertDetailSheetState();
}

class _AlertDetailSheetState extends State<_AlertDetailSheet> {
  bool    _triaging   = false;
  String? _aiAnalysis;
  Map<String,dynamic>? _investigation;
  bool _loadingInvestigation = true;

  @override void initState() { super.initState(); _loadInvestigation(); }

  Future<void> _loadInvestigation() async {
    final id = widget.alert['id'] as int? ?? 0;
    final r  = await widget.api.alertInvestigation(id);
    if (!mounted) return;
    setState(() { _investigation = r; _loadingInvestigation = false; });
  }

  Future<void> _triage() async {
    final id = widget.alert['id'] as int? ?? 0;
    setState(() => _triaging = true);
    await widget.api.triageAlert(id);
    if (!mounted) return;
    setState(() { _triaging = false; _aiAnalysis = 'AI triage initiated — check AI Assistant for results.'; });
  }

  @override
  Widget build(BuildContext context) {
    final a   = widget.alert;
    final id  = a['id'] as int? ?? 0;
    final col = sevColor(str(a['severity']));
    final cs  = Theme.of(context).colorScheme;

    return DraggableScrollableSheet(
      initialChildSize: 0.72,
      maxChildSize: 0.95,
      minChildSize: 0.4,
      expand: false,
      builder: (_, ctrl) => Container(
        decoration: BoxDecoration(
          color: cs.surface,
          borderRadius: const BorderRadius.vertical(top: Radius.circular(20))),
        child: Column(children: [
          Center(child: Container(
            width: 38, height: 4, margin: const EdgeInsets.symmetric(vertical: 10),
            decoration: BoxDecoration(color: cs.outlineVariant, borderRadius: BorderRadius.circular(2)))),
          Padding(
            padding: const EdgeInsets.fromLTRB(16, 0, 16, 12),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Container(width: 6, height: 6, decoration: BoxDecoration(color: col, shape: BoxShape.circle)),
                const SizedBox(width: 8),
                SevChip(str(a['severity'])),
                const Spacer(),
                IconButton(
                  icon: const Icon(Icons.copy, size: 16),
                  onPressed: () => copyToClipboard(context, '${str(a['rule_name'])} — ${str(a['hostname'] ?? '')}'),
                  tooltip: 'Copy details',
                ),
                IconButton(icon: const Icon(Icons.close), onPressed: () => Navigator.pop(context)),
              ]),
              const SizedBox(height: 6),
              Text(str(a['rule_name'] ?? a['message'] ?? 'Alert'),
                style: const TextStyle(fontSize: 17, fontWeight: FontWeight.w800)),
              const SizedBox(height: 4),
              Text(timeAgo(a['created_at']), style: const TextStyle(fontSize: 12, color: Colors.grey)),
            ]),
          ),
          const Divider(height: 1),
          Expanded(child: ListView(
            controller: ctrl,
            padding: const EdgeInsets.fromLTRB(16, 12, 16, 24),
            children: [
              if (_aiAnalysis != null)
                Container(
                  margin: const EdgeInsets.only(bottom: 14),
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF6366F1).withValues(alpha: .07),
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: const Color(0xFF6366F1).withValues(alpha: .2))),
                  child: Row(children: [
                    const Icon(Icons.psychology, size: 16, color: Color(0xFF6366F1)),
                    const SizedBox(width: 8),
                    Expanded(child: Text(_aiAnalysis!,
                      style: const TextStyle(fontSize: 12, color: Color(0xFF6366F1)))),
                  ]),
                ),
              SectionTitle('Details'),
              InfoPair('Alert ID',  str(id)),
              InfoPair('Status',    str(a['status'])),
              InfoPair('Hostname',  str(a['hostname']  ?? '—')),
              InfoPair('Agent ID',  str(a['agent_id']  ?? '—')),
              InfoPair('Fingerprint', str(a['fingerprint'] ?? '—')),
              if (str(a['log_message'], '').isNotEmpty) ...[
                const SizedBox(height: 10),
                SectionTitle('Log Message'),
                Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: cs.surfaceContainerLow,
                    borderRadius: BorderRadius.circular(8)),
                  child: SelectableText(str(a['log_message']),
                    style: const TextStyle(fontSize: 11.5, fontFamily: 'monospace')),
                ),
              ],
              // Alert model has no mitre_technique_id — real key is mitre_technique.
              if (a['mitre_technique'] != null || a['mitre_tactic'] != null) ...[
                const SizedBox(height: 12),
                SectionTitle('MITRE ATT&CK'),
                Wrap(spacing: 6, runSpacing: 4, children: [
                  if (str(a['mitre_technique'], '').isNotEmpty) _MitreTag(str(a['mitre_technique'])),
                  if (str(a['mitre_tactic'], '').isNotEmpty) _MitreTag(str(a['mitre_tactic'])),
                  if (str(a['mitre_name'], '').isNotEmpty) _MitreTag(str(a['mitre_name'])),
                ]),
              ],
              const SizedBox(height: 14),
              SectionTitle('Investigation',
                trailing: _loadingInvestigation
                  ? const SizedBox(width: 12, height: 12, child: CircularProgressIndicator(strokeWidth: 2))
                  : null),
              if (!_loadingInvestigation) ...[
                if (_investigation == null)
                  const Text('Investigation data unavailable.', style: TextStyle(fontSize: 12, color: Colors.grey))
                else ...[
                  InfoPair('Threat Score', str(_investigation!['threat_score'], '0')),
                  if ((_investigation!['ioc_hits'] as List?)?.isNotEmpty ?? false) ...[
                    const SizedBox(height: 6),
                    const Text('IOC Hits', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Colors.grey)),
                    ...((_investigation!['ioc_hits'] as List).map((h) {
                      final hit = h as Map<String,dynamic>;
                      return Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Text('${str(hit['type'])}: ${str(hit['indicator'])}',
                          style: const TextStyle(fontSize: 12, fontFamily: 'monospace')));
                    })),
                  ],
                  if ((_investigation!['similar_alerts'] as List?)?.isNotEmpty ?? false) ...[
                    const SizedBox(height: 8),
                    const Text('Similar Alerts', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Colors.grey)),
                    ...((_investigation!['similar_alerts'] as List).take(5).map((s) {
                      final sim = s as Map<String,dynamic>;
                      return Padding(
                        padding: const EdgeInsets.only(top: 4),
                        child: Text('${str(sim['rule_name'])} — ${str(sim['hostname'])}',
                          style: const TextStyle(fontSize: 12)));
                    })),
                  ],
                ],
              ],
              const SizedBox(height: 16),
            ],
          )),
          SafeArea(child: Padding(
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
            child: Row(children: [
              Expanded(child: FilledButton.icon(
                onPressed: () async {
                  await widget.api.ackAlert(id);
                  widget.onAction();
                  if (context.mounted) Navigator.pop(context);
                },
                icon: const Icon(Icons.check_circle_outline, size: 16),
                label: const Text('Acknowledge'),
                style: FilledButton.styleFrom(backgroundColor: const Color(0xFF22C55E)),
              )),
              const SizedBox(width: 8),
              Expanded(child: FilledButton.icon(
                onPressed: () async {
                  await widget.api.resolveAlert(id);
                  widget.onAction();
                  if (context.mounted) Navigator.pop(context);
                },
                icon: const Icon(Icons.done_all, size: 16),
                label: const Text('Resolve'),
                style: FilledButton.styleFrom(backgroundColor: Colors.blueGrey),
              )),
              const SizedBox(width: 8),
              IconButton.outlined(
                onPressed: _triaging ? null : _triage,
                icon: _triaging
                  ? const SizedBox(width: 16, height: 16, child: CircularProgressIndicator(strokeWidth: 2))
                  : const Icon(Icons.psychology, size: 18),
                tooltip: 'AI Triage',
              ),
            ]),
          )),
        ]),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Incidents Screen
// ─────────────────────────────────────────────────────────────────────────────

class IncidentsScreen extends StatefulWidget {
  final DashboardApi api;
  const IncidentsScreen({super.key, required this.api});
  @override State<IncidentsScreen> createState() => _IncidentsState();
}

class _IncidentsState extends State<IncidentsScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  final _statuses = ['open', 'investigating', 'contained', 'resolved'];
  List   _incidents = [];
  bool   _loading   = true;
  String _status    = 'open';

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 4, vsync: this);
    _tabs.addListener(() {
      if (!_tabs.indexIsChanging) {
        setState(() => _status = _statuses[_tabs.index]);
        _load();
      }
    });
    _load();
  }

  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.incidents(status: _status, per: 50);
    if (!mounted) return;
    setState(() { _incidents = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(
        controller: _tabs,
        labelStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
        tabs: const [
          Tab(text: 'Open'), Tab(text: 'Investigating'),
          Tab(text: 'Contained'), Tab(text: 'Resolved'),
        ],
      ),
      Expanded(child: _loading
        ? xLoading()
        : _incidents.isEmpty
          ? const XEmptyState('No incidents', icon: Icons.bolt_outlined)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
                itemCount: _incidents.length,
                itemBuilder: (_, i) => _IncidentCard(
                  incident: _incidents[i] as Map<String,dynamic>,
                  api: widget.api,
                  onAction: _load,
                ),
              ),
            )),
    ]);
  }
}

class _IncidentCard extends StatelessWidget {
  final Map<String,dynamic> incident;
  final DashboardApi api;
  final VoidCallback onAction;
  const _IncidentCard({required this.incident, required this.api, required this.onAction});

  void _showEvents(BuildContext context) {
    final id = incident['id'] as int? ?? 0;
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => DraggableScrollableSheet(
        initialChildSize: 0.6, maxChildSize: 0.9, minChildSize: 0.3, expand: false,
        builder: (_, ctrl) => FutureBuilder<List>(
          future: api.incidentEvents(id),
          builder: (ctx2, snap) {
            final events = snap.data ?? [];
            return Column(children: [
              sheetHeader('Incident Timeline'),
              Expanded(child: !snap.hasData
                ? const Center(child: CircularProgressIndicator())
                : events.isEmpty
                  ? const Center(child: Text('No events recorded', style: TextStyle(color: Colors.grey)))
                  : ListView.builder(
                      controller: ctrl,
                      padding: const EdgeInsets.fromLTRB(16, 0, 16, 16),
                      itemCount: events.length,
                      itemBuilder: (_, i) {
                        final e = events[i] as Map<String,dynamic>;
                        return Padding(
                          padding: const EdgeInsets.only(bottom: 10),
                          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text(str(e['event_type'], 'event'),
                              style: const TextStyle(fontWeight: FontWeight.w700, fontSize: 12.5)),
                            Text(str(e['details']), style: const TextStyle(fontSize: 12, color: Colors.grey)),
                            Text(timeAgo(e['created_at']), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                          ]),
                        );
                      },
                    )),
            ]);
          },
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final inc = incident;
    final id  = inc['id'] as int? ?? 0;

    return Card(
      margin: const EdgeInsets.only(bottom: 10),
      child: InkWell(
        onTap: () => _showEvents(context),
        child: Padding(
        padding: const EdgeInsets.all(14),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Expanded(child: Text(str(inc['title']),
              style: const TextStyle(fontSize: 14, fontWeight: FontWeight.w700))),
            SevChip(str(inc['severity'])),
            const SizedBox(width: 6),
            StatusChip(str(inc['status'])),
            PopupMenuButton<String>(
              onSelected: (action) async {
                if (['investigating', 'contained', 'resolved'].contains(action)) {
                  final ok = await api.updateIncidentStatus(id, action);
                  if (context.mounted) xSnack(context, ok ? 'Status updated' : 'Failed', error: !ok);
                  onAction();
                  return;
                }
                if (['critical','high','medium','low'].contains(action)) {
                  final ok = await api.updateIncidentSeverity(id, action);
                  if (context.mounted) xSnack(context, ok ? 'Severity updated' : 'Failed', error: !ok);
                  onAction();
                  return;
                }
                if (action == 'note') {
                  final ctrl = TextEditingController();
                  if (!context.mounted) return;
                  await showDialog(context: context, builder: (_) => AlertDialog(
                    title: const Text('Add Note'),
                    content: TextField(controller: ctrl, maxLines: 3,
                      decoration: const InputDecoration(hintText: 'Note text…')),
                    actions: [
                      TextButton(onPressed: () => Navigator.pop(context), child: const Text('Cancel')),
                      FilledButton(onPressed: () async {
                        Navigator.pop(context);
                        final ok = await api.addIncidentNote(id, ctrl.text);
                        if (context.mounted) xSnack(context, ok ? 'Note added' : 'Failed', error: !ok);
                      }, child: const Text('Add')),
                    ],
                  ));
                }
              },
              itemBuilder: (_) => [
                const PopupMenuItem(value: 'investigating', child: Text('→ Investigating')),
                const PopupMenuItem(value: 'contained',    child: Text('→ Contained')),
                const PopupMenuItem(value: 'resolved',     child: Text('→ Resolved')),
                const PopupMenuDivider(),
                const PopupMenuItem(value: 'critical', child: Text('Severity: Critical')),
                const PopupMenuItem(value: 'high',     child: Text('Severity: High')),
                const PopupMenuItem(value: 'medium',   child: Text('Severity: Medium')),
                const PopupMenuItem(value: 'low',      child: Text('Severity: Low')),
                const PopupMenuDivider(),
                const PopupMenuItem(value: 'note',         child: Text('Add Note')),
              ],
            ),
          ]),
          const SizedBox(height: 8),
          if (inc['description'] != null)
            Text(str(inc['description']),
              style: const TextStyle(fontSize: 12.5, color: Colors.grey),
              maxLines: 2, overflow: TextOverflow.ellipsis),
          const SizedBox(height: 10),
          Row(children: [
            const Icon(Icons.access_time, size: 13, color: Colors.grey),
            const SizedBox(width: 4),
            Text(timeAgo(inc['created_at']), style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            // models.Incident (models/incident.go:5) has no affected_hosts
            // list — an incident is tied to exactly one agent, real field
            // is the singular hostname.
            if ((inc['hostname'] ?? '').toString().isNotEmpty) ...[
              const SizedBox(width: 12),
              const Icon(Icons.computer, size: 13, color: Colors.grey),
              const SizedBox(width: 4),
              Text(str(inc['hostname']),
                style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
            ],
          ]),
        ]),
        ),
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// UEBA Screen
// ─────────────────────────────────────────────────────────────────────────────

class UEBAScreen extends StatefulWidget {
  final DashboardApi api;
  const UEBAScreen({super.key, required this.api});
  @override State<UEBAScreen> createState() => _UEBAState();
}

class _UEBAState extends State<UEBAScreen> {
  List _users   = [];
  List _events  = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.uebaUsers().then((r)  => _users  = r),
      widget.api.uebaEvents().then((r) => _events = r),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Row(children: [
            Expanded(child: KpiCard(label: 'Users Monitored', value: '${_users.length}',
              color: const Color(0xFF3B82F6), icon: Icons.person_search)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Anomalous Events', value: '${_events.length}',
              color: const Color(0xFFF97316), icon: Icons.warning_amber)),
          ]),
          const SizedBox(height: 16),
          Row(children: [
            const Expanded(child: SectionTitle('High-Risk Users')),
            TextButton.icon(
              onPressed: () async {
                final ok = await widget.api.triggerUEBA();
                if (context.mounted) xSnack(context, ok ? 'UEBA analysis triggered' : 'Failed', error: !ok);
              },
              icon: const Icon(Icons.refresh, size: 14),
              label: const Text('Analyze', style: TextStyle(fontSize: 12)),
            ),
          ]),
          ..._users.take(20).map((u) {
            final user     = u as Map<String,dynamic>;
            final username = str(user['username'] ?? user['email']);
            // GetInsiderThreatScores (api/insider_threat.go:16) — real field is score.
            final score = (user['score'] ?? 0) is num ? (user['score'] as num).toInt() : 0;
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(10),
                color: Theme.of(context).colorScheme.surfaceContainerLow),
              child: Row(children: [
                CircleAvatar(radius: 18,
                  child: Text((str(user['username'], 'U')[0]).toUpperCase())),
                const SizedBox(width: 12),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(username,
                    style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 4),
                  HealthBar(100 - score),
                ])),
                const SizedBox(width: 10),
                Text('$score', style: TextStyle(
                  fontSize: 16, fontWeight: FontWeight.w900,
                  color: score > 70 ? const Color(0xFFEF4444)
                       : score > 40 ? const Color(0xFFF59E0B)
                       :               const Color(0xFF22C55E))),
                PopupMenuButton<String>(
                  onSelected: (v) async {
                    bool ok;
                    if (v == 'logout') {
                      ok = await widget.api.forceLogoutUebaUser(username);
                    } else {
                      ok = await widget.api.addUebaWatchlist(username);
                    }
                    if (context.mounted) xSnack(context, ok ? 'Done' : 'Failed', error: !ok);
                    _load();
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(value: 'logout', child: Text('Force Logout')),
                    PopupMenuItem(value: 'watchlist', child: Text('Add to Watchlist')),
                  ],
                ),
              ]),
            );
          }),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Insider Threat Screen
// ─────────────────────────────────────────────────────────────────────────────

class InsiderThreatScreen extends StatefulWidget {
  final DashboardApi api;
  const InsiderThreatScreen({super.key, required this.api});
  @override State<InsiderThreatScreen> createState() => _InsiderThreatState();
}

class _InsiderThreatState extends State<InsiderThreatScreen> {
  List                 _scores  = [];
  Map<String,dynamic>? _summary;
  bool                 _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.insiderThreat().then((r) => _scores  = r),
      widget.api.insiderSummary().then((r) => _summary = r),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    final summary = _summary ?? {};
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          Row(children: [
            Expanded(child: KpiCard(label: 'High Risk',   value: str(summary['high_risk']   ?? 0),
              color: const Color(0xFFEF4444), icon: Icons.person_off)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Medium Risk', value: str(summary['medium_risk'] ?? 0),
              color: const Color(0xFFF59E0B), icon: Icons.warning)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Low Risk',    value: str(summary['low_risk']    ?? 0),
              color: const Color(0xFF22C55E), icon: Icons.verified_user)),
          ]),
          const SizedBox(height: 16),
          SectionTitle('Threat Scores'),
          ..._scores.take(20).map((s) {
            final score    = s as Map<String,dynamic>;
            final username = str(score['username'] ?? score['user_id']);
            // GetInsiderThreatScores (api/insider_threat.go:16) — real field is score.
            final val   = (score['score'] ?? 0) is num
              ? (score['score'] ?? 0).toInt() : 0;
            final col   = val > 70 ? const Color(0xFFEF4444)
                        : val > 40 ? const Color(0xFFF59E0B)
                        :             const Color(0xFF22C55E);
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.fromLTRB(14, 12, 14, 12),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(10),
                color: col.withValues(alpha: .05),
                border: Border.all(color: col.withValues(alpha: .2))),
              child: Row(children: [
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(username,
                    style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700)),
                  const SizedBox(height: 4),
                  Text(str(score['reason'] ?? score['details'] ?? ''),
                    style: const TextStyle(fontSize: 11.5, color: Colors.grey),
                    maxLines: 1, overflow: TextOverflow.ellipsis),
                ])),
                const SizedBox(width: 12),
                Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                  Text('$val', style: TextStyle(
                    fontSize: 22, fontWeight: FontWeight.w900, color: col)),
                  const Text('/ 100', style: TextStyle(fontSize: 10, color: Colors.grey)),
                ]),
                PopupMenuButton<String>(
                  onSelected: (v) async {
                    bool ok;
                    if (v == 'logout') {
                      ok = await widget.api.forceLogoutInsiderUser(username);
                    } else {
                      ok = await widget.api.addInsiderWatchlist(username);
                    }
                    if (context.mounted) xSnack(context, ok ? 'Done' : 'Failed', error: !ok);
                    _load();
                  },
                  itemBuilder: (_) => const [
                    PopupMenuItem(value: 'logout', child: Text('Force Logout')),
                    PopupMenuItem(value: 'watchlist', child: Text('Add to Watchlist')),
                  ],
                ),
              ]),
            );
          }),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NBA (Network Behavior Anomaly) Screen
// ─────────────────────────────────────────────────────────────────────────────

class NBAScreen extends StatefulWidget {
  final DashboardApi api;
  const NBAScreen({super.key, required this.api});
  @override State<NBAScreen> createState() => _NBAState();
}

class _NBAState extends State<NBAScreen> {
  List _anomalies = [];
  bool _loading   = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _anomalies = await widget.api.nbaAnomalies();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_anomalies.isEmpty) {
      return RefreshIndicator(
        onRefresh: _load,
        child: const XEmptyState('No network anomalies', icon: Icons.lan_outlined));
    }
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 4),
        child: Row(children: [
          Expanded(child: KpiCard(label: 'Anomalies', value: '${_anomalies.length}',
            color: const Color(0xFFF97316), icon: Icons.ssid_chart)),
          const SizedBox(width: 8),
          TextButton.icon(
            onPressed: () async {
              final ok = await widget.api.triggerNBA();
              if (context.mounted) xSnack(context, ok ? 'Analysis triggered' : 'Failed', error: !ok);
            },
            icon: const Icon(Icons.play_arrow, size: 14),
            label: const Text('Run Analysis', style: TextStyle(fontSize: 12)),
          ),
        ]),
      ),
      Expanded(child: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
          itemCount: _anomalies.length,
          itemBuilder: (_, i) {
            // NetworkAnomaly has no `severity` field — derive a label from
            // the real deviation_score (0-100-ish, higher = more anomalous).
            final a    = _anomalies[i] as Map<String,dynamic>;
            final id   = a['id'] as int? ?? 0;
            final dev  = (a['deviation_score'] as num?)?.toInt() ?? 0;
            final sev  = dev >= 80 ? 'critical' : dev >= 60 ? 'high' : dev >= 40 ? 'medium' : 'low';
            final col  = sevColor(sev);
            return Container(
              margin: const EdgeInsets.only(bottom: 8),
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: col.withValues(alpha: .25)),
                color: col.withValues(alpha: .04)),
              child: Row(children: [
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Expanded(child: Text(str(a['anomaly_type'], 'Anomaly'),
                      style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700))),
                    SevChip(sev),
                  ]),
                  const SizedBox(height: 4),
                  Text(str(a['description'], ''),
                    style: const TextStyle(fontSize: 12, color: Colors.grey),
                    maxLines: 2, overflow: TextOverflow.ellipsis),
                  const SizedBox(height: 6),
                  Text('Score $dev  ·  ${timeAgo(a['detected_at'])}',
                    style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                ])),
                const SizedBox(width: 8),
                IconButton(
                  icon: const Icon(Icons.check_circle_outline, color: Color(0xFF22C55E)),
                  onPressed: () async {
                    final ok = await widget.api.ackNbaAnomaly(id);
                    if (context.mounted) xSnack(context, ok ? 'Acknowledged' : 'Failed', error: !ok);
                    _load();
                  },
                ),
              ]),
            );
          },
        ),
      )),
    ]);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Deep Inspection (DPI)
// ─────────────────────────────────────────────────────────────────────────────
// Mobile cut of the desktop /dpi page (real KPIs + sessions + files/DLP +
// protocol anomalies + a single-shot AI inspector button) — not a literal
// port of the 1300-line desktop page's HTTP/DNS/TLS/analytics/performance
// sub-tabs or its raw response-action console; see class docs on parity.

class DeepInspectionScreen extends StatefulWidget {
  final DashboardApi api;
  const DeepInspectionScreen({super.key, required this.api});
  @override State<DeepInspectionScreen> createState() => _DeepInspectionState();
}

class _DeepInspectionState extends State<DeepInspectionScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  final _loadedTabs = <int>{};

  Map<String,dynamic>? _overview;
  List _sessions        = [];
  List _files           = [];
  List _dlp             = [];
  List _protoAnomalies  = [];

  bool _loadingOverview = true;
  bool _loadingSessions = false;
  bool _loadingFiles    = false;
  bool _loadingProto    = false;

  Map<String,dynamic>? _ai;
  bool _aiLoading = false;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 4, vsync: this);
    _tabs.addListener(() {
      if (!_tabs.indexIsChanging) _loadTab(_tabs.index);
    });
    _loadOverview();
  }

  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _loadTab(int i) async {
    if (_loadedTabs.contains(i)) return;
    _loadedTabs.add(i);
    switch (i) {
      case 1: await _loadSessions();  break;
      case 2: await _loadFilesDlp();  break;
      case 3: await _loadProtoAnomalies(); break;
    }
  }

  Future<void> _loadOverview() async {
    setState(() => _loadingOverview = true);
    final r = await widget.api.dpiOverview();
    if (!mounted) return;
    setState(() { _overview = r; _loadingOverview = false; });
  }

  Future<void> _loadSessions() async {
    setState(() => _loadingSessions = true);
    final r = await widget.api.dpiSessions();
    if (!mounted) return;
    setState(() { _sessions = r; _loadingSessions = false; });
  }

  Future<void> _loadFilesDlp() async {
    setState(() => _loadingFiles = true);
    final f = await widget.api.dpiFiles();
    final d = await widget.api.dpiDlp();
    if (!mounted) return;
    setState(() { _files = f; _dlp = d; _loadingFiles = false; });
  }

  Future<void> _loadProtoAnomalies() async {
    setState(() => _loadingProto = true);
    final r = await widget.api.dpiProtocolAnomalies();
    if (!mounted) return;
    setState(() { _protoAnomalies = r; _loadingProto = false; });
  }

  Future<void> _runAiInspect() async {
    setState(() => _aiLoading = true);
    final r = await widget.api.dpiAiInspect();
    if (!mounted) return;
    setState(() { _ai = r; _aiLoading = false; });
  }

  Future<void> _refreshCurrent() async {
    switch (_tabs.index) {
      case 0: return _loadOverview();
      case 1: return _loadSessions();
      case 2: return _loadFilesDlp();
      case 3: return _loadProtoAnomalies();
    }
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(
        controller: _tabs,
        isScrollable: true,
        labelStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
        tabs: const [
          Tab(text: 'Overview'), Tab(text: 'Sessions'),
          Tab(text: 'Files & DLP'), Tab(text: 'Protocol Anomalies'),
        ],
      ),
      Expanded(child: TabBarView(
        controller: _tabs,
        children: [
          _buildOverview(),
          _buildSessions(),
          _buildFilesDlp(),
          _buildProtoAnomalies(),
        ],
      )),
    ]);
  }

  Widget _buildOverview() {
    if (_loadingOverview) return xLoading();
    final ov = _overview;
    if (ov == null) {
      return RefreshIndicator(onRefresh: _loadOverview,
        child: const XEmptyState('DPI overview unavailable', icon: Icons.search_off));
    }
    final breakdown = (ov['finding_breakdown'] as List?) ?? [];
    return RefreshIndicator(
      onRefresh: _refreshCurrent,
      child: ListView(
        padding: const EdgeInsets.all(12),
        children: [
          GridView.count(
            crossAxisCount: 2,
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            crossAxisSpacing: 8, mainAxisSpacing: 8,
            childAspectRatio: 1.7,
            children: [
              KpiCard(label: 'Total Findings', value: str(ov['total_findings'], '0'),
                color: const Color(0xFFF97316), icon: Icons.search),
              KpiCard(label: 'Alerted', value: str(ov['alerted_findings'], '0'),
                color: const Color(0xFFEF4444), icon: Icons.notifications_active),
              KpiCard(label: 'Sessions', value: str(ov['total_sessions'], '0'),
                color: const Color(0xFF3B82F6), icon: Icons.hub),
              KpiCard(label: 'Malware', value: str(ov['malware_detected'], '0'),
                color: const Color(0xFFEF4444), icon: Icons.bug_report),
              KpiCard(label: 'DLP Violations', value: str(ov['dlp_violations'], '0'),
                color: const Color(0xFFF59E0B), icon: Icons.policy),
              KpiCard(label: 'Protocol Anomalies', value: str(ov['protocol_anomalies'], '0'),
                color: const Color(0xFF8B5CF6), icon: Icons.warning_amber),
            ],
          ),
          const SizedBox(height: 12),
          Row(children: [
            _MiniStat(label: 'Encrypted', value: str(ov['encrypted_traffic'], '0')),
            _MiniStat(label: 'HTTP', value: str(ov['http_sessions'], '0')),
            _MiniStat(label: 'DNS', value: str(ov['dns_queries'], '0')),
            _MiniStat(label: 'TLS', value: str(ov['tls_connections'], '0'), last: true),
          ]),
          if (breakdown.isNotEmpty) ...[
            const SizedBox(height: 16),
            SectionTitle('Finding Types'),
            ...breakdown.map((f) {
              final e = f as Map<String,dynamic>;
              return Padding(
                padding: const EdgeInsets.only(bottom: 6),
                child: Row(children: [
                  Expanded(child: Text(str(e['type']), style: const TextStyle(fontSize: 12.5))),
                  Text(str(e['count'], '0'), style: const TextStyle(fontSize: 12.5, fontWeight: FontWeight.w700)),
                ]),
              );
            }),
          ],
          const SizedBox(height: 16),
          SectionTitle('AI Threat Inspector'),
          SizedBox(width: double.infinity, child: OutlinedButton.icon(
            onPressed: _aiLoading ? null : _runAiInspect,
            icon: _aiLoading
              ? const SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2))
              : const Icon(Icons.smart_toy_outlined, size: 16),
            label: Text(_aiLoading ? 'Analyzing…' : 'Run AI Inspection'),
          )),
          if (_ai != null) ...[
            const SizedBox(height: 10),
            if (_ai!['error'] != null)
              Text(str(_ai!['error']), style: const TextStyle(fontSize: 12, color: Color(0xFFEF4444)))
            else
              Container(
                width: double.infinity,
                padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(
                  color: Theme.of(context).colorScheme.surfaceContainerLow,
                  borderRadius: BorderRadius.circular(10)),
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    const Text('Risk: ', style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700)),
                    SevChip(str(_ai!['risk_level'], 'low')),
                  ]),
                  const SizedBox(height: 8),
                  Text(str(_ai!['threat_summary']), style: const TextStyle(fontSize: 12.5)),
                  if (_ai!['recommendations'] is List && (_ai!['recommendations'] as List).isNotEmpty) ...[
                    const SizedBox(height: 8),
                    const Text('Recommendations', style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, color: Colors.grey)),
                    ...(_ai!['recommendations'] as List).map((r) => Text('• $r', style: const TextStyle(fontSize: 12))),
                  ],
                ]),
              ),
          ],
          const SizedBox(height: 30),
        ],
      ),
    );
  }

  Widget _buildSessions() {
    if (_loadingSessions) return xLoading();
    if (_sessions.isEmpty) {
      return RefreshIndicator(onRefresh: _loadSessions,
        child: const XEmptyState('No active DPI sessions', icon: Icons.hub_outlined));
    }
    return RefreshIndicator(
      onRefresh: _loadSessions,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: _sessions.length,
        itemBuilder: (_, i) {
          final s    = _sessions[i] as Map<String,dynamic>;
          final susp = s['is_suspicious'] == true;
          final col  = susp ? const Color(0xFFEF4444) : const Color(0xFF3B82F6);
          return Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: col.withValues(alpha: .25)),
              color: col.withValues(alpha: .04)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Icon(s['is_encrypted'] == true ? Icons.lock_outline : Icons.lock_open, size: 14, color: col),
                const SizedBox(width: 6),
                Expanded(child: Text(str(s['hostname']),
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
                if (susp) const SevChip('high'),
              ]),
              const SizedBox(height: 4),
              Text('${str(s['remote_address'])}  ·  ${str(s['app_proto'] ?? s['protocol'])}',
                style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
              if (str(s['http_host'] ?? s['sni'], '').isNotEmpty) ...[
                const SizedBox(height: 2),
                Text(str(s['http_host'] ?? s['sni']),
                  style: const TextStyle(fontSize: 11, color: Colors.grey)),
              ],
              const SizedBox(height: 6),
              Row(children: [
                Text('${str(s['conn_count'], '0')} conns', style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                const SizedBox(width: 10),
                Text('last ${timeAgo(s['last_seen'])}', style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
              ]),
            ]),
          );
        },
      ),
    );
  }

  Widget _buildFilesDlp() {
    if (_loadingFiles) return xLoading();
    // Files' JSON key is `finding_type`; DLP's real column is aliased to
    // `category` (see DashboardApi.dpiDlp) — check both so neither list
    // renders a blank type label.
    final List<Map<String,dynamic>> combined = [
      for (final f in _files) {...f as Map<String,dynamic>, '_kind': 'file'},
      for (final d in _dlp)   {...d as Map<String,dynamic>, '_kind': 'dlp'},
    ]..sort((a, b) => str(b['detected_at']).compareTo(str(a['detected_at'])));

    if (combined.isEmpty) {
      return RefreshIndicator(onRefresh: _loadFilesDlp,
        child: const XEmptyState('No file or DLP findings', icon: Icons.shield_outlined));
    }
    return RefreshIndicator(
      onRefresh: _loadFilesDlp,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: combined.length,
        itemBuilder: (_, i) {
          final f      = combined[i];
          final col    = sevColor(str(f['severity']));
          final isFile = f['_kind'] == 'file';
          return Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: col.withValues(alpha: .25)),
              color: col.withValues(alpha: .04)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Icon(isFile ? Icons.description_outlined : Icons.policy_outlined, size: 14, color: col),
                const SizedBox(width: 6),
                Expanded(child: Text(str(f['finding_type'] ?? f['category'], 'Finding'),
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
                SevChip(str(f['severity'])),
              ]),
              const SizedBox(height: 4),
              Text(str(f['description']),
                style: const TextStyle(fontSize: 12, color: Colors.grey),
                maxLines: 2, overflow: TextOverflow.ellipsis),
              const SizedBox(height: 6),
              Row(children: [
                Expanded(child: Text(str(f['indicator']),
                  style: const TextStyle(fontSize: 10.5, color: Colors.grey, fontFamily: 'monospace'),
                  maxLines: 1, overflow: TextOverflow.ellipsis)),
                Text(timeAgo(f['detected_at']), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
              ]),
            ]),
          );
        },
      ),
    );
  }

  Widget _buildProtoAnomalies() {
    if (_loadingProto) return xLoading();
    if (_protoAnomalies.isEmpty) {
      return RefreshIndicator(onRefresh: _loadProtoAnomalies,
        child: const XEmptyState('No protocol anomalies', icon: Icons.rule_folder_outlined));
    }
    return RefreshIndicator(
      onRefresh: _loadProtoAnomalies,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: _protoAnomalies.length,
        itemBuilder: (_, i) {
          final a   = _protoAnomalies[i] as Map<String,dynamic>;
          final col = sevColor(str(a['severity']));
          return Container(
            margin: const EdgeInsets.only(bottom: 8),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: col.withValues(alpha: .25)),
              color: col.withValues(alpha: .04)),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(child: Text(str(a['finding_type'], 'Anomaly'),
                  style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700))),
                SevChip(str(a['severity'])),
              ]),
              const SizedBox(height: 4),
              Text(str(a['description']),
                style: const TextStyle(fontSize: 12, color: Colors.grey),
                maxLines: 2, overflow: TextOverflow.ellipsis),
              const SizedBox(height: 6),
              Text(timeAgo(a['detected_at']), style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            ]),
          );
        },
      ),
    );
  }
}

class _MiniStat extends StatelessWidget {
  final String label, value;
  final bool last;
  const _MiniStat({required this.label, required this.value, this.last = false});
  @override
  Widget build(BuildContext context) => Expanded(child: Container(
    margin: EdgeInsets.only(right: last ? 0 : 6),
    padding: const EdgeInsets.symmetric(vertical: 8),
    decoration: BoxDecoration(
      color: Theme.of(context).colorScheme.surfaceContainerLow,
      borderRadius: BorderRadius.circular(8)),
    child: Column(children: [
      Text(value, style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w800)),
      Text(label, style: const TextStyle(fontSize: 9.5, color: Colors.grey)),
    ]),
  ));
}

// ─────────────────────────────────────────────────────────────────────────────
// Alert Clusters Screen
// ─────────────────────────────────────────────────────────────────────────────

class ClustersScreen extends StatefulWidget {
  final DashboardApi api;
  const ClustersScreen({super.key, required this.api});
  @override State<ClustersScreen> createState() => _ClustersState();
}

class _ClustersState extends State<ClustersScreen> {
  List _clusters = [];
  bool _loading  = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _clusters = await widget.api.clusters();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    if (_clusters.isEmpty) {
      return RefreshIndicator(
        onRefresh: _load,
        child: const XEmptyState('No alert clusters', icon: Icons.hub_outlined));
    }
    return Column(children: [
      Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
        child: Row(children: [
          const Expanded(child: SectionTitle('Alert Clusters')),
          TextButton.icon(
            onPressed: () async {
              final ok = await widget.api.triggerClustering();
              if (context.mounted) xSnack(context, ok ? 'Clustering triggered' : 'Failed', error: !ok);
            },
            icon: const Icon(Icons.hub, size: 14),
            label: const Text('Re-cluster', style: TextStyle(fontSize: 12)),
          ),
        ]),
      ),
      Expanded(child: RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(12, 0, 12, 80),
          itemCount: _clusters.length,
          itemBuilder: (_, i) {
            final cl  = _clusters[i] as Map<String,dynamic>;
            final id  = cl['id'] as int? ?? 0;
            final cnt = (cl['alert_count'] ?? cl['count'] ?? 0) is num
              ? (cl['alert_count'] ?? cl['count'] ?? 0).toInt() : 0;
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: CircleAvatar(
                  backgroundColor: const Color(0xFF6366F1).withValues(alpha: .12),
                  child: Text('$cnt', style: const TextStyle(
                    fontWeight: FontWeight.w900, color: Color(0xFF6366F1)))),
                // models.AlertCluster (models/dfir.go:48) has no cluster_name/
                // name/severity/created_at — real fields are rule_name (title),
                // mitre_technique, and first_seen/last_seen (no severity at all).
                title: Text(str(cl['rule_name'] ?? cl['cluster_key'], 'Cluster $id'),
                  style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('${str(cl['mitre_technique'], 'uncategorized')} · last seen ${timeAgo(cl['last_seen'])}'),
                trailing: IconButton(
                  icon: const Icon(Icons.do_not_disturb, color: Color(0xFFF97316)),
                  tooltip: 'Suppress',
                  onPressed: () async {
                    final ok = await widget.api.suppressCluster(id);
                    if (context.mounted) xSnack(context, ok ? 'Cluster suppressed' : 'Failed', error: !ok);
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

// ─────────────────────────────────────────────────────────────────────────────
// Correlation Rules Screen
// ─────────────────────────────────────────────────────────────────────────────

class CorrelationScreen extends StatefulWidget {
  final DashboardApi api;
  const CorrelationScreen({super.key, required this.api});
  @override State<CorrelationScreen> createState() => _CorrelationState();
}

class _CorrelationState extends State<CorrelationScreen> {
  List _rules   = [];
  List _matches = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.correlationRules().then((r)   => _rules   = r),
      widget.api.correlationMatches().then((r) => _matches = r),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton(onPressed: _createRule, child: const Icon(Icons.add)),
      body: RefreshIndicator(
      onRefresh: _load,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(12, 12, 12, 80),
        children: [
          Row(children: [
            Expanded(child: KpiCard(label: 'Rules',   value: '${_rules.length}',
              color: const Color(0xFF3B82F6), icon: Icons.rule)),
            const SizedBox(width: 8),
            Expanded(child: KpiCard(label: 'Matches', value: '${_matches.length}',
              color: const Color(0xFFF97316), icon: Icons.link)),
          ]),
          const SizedBox(height: 16),
          SectionTitle('Correlation Rules'),
          ..._rules.map((r) {
            final rule    = r as Map<String,dynamic>;
            final id      = rule['id'] as int? ?? 0;
            final enabled = rule['enabled'] == true;
            return Card(
              margin: const EdgeInsets.only(bottom: 8),
              child: ListTile(
                leading: Switch(
                  value: enabled,
                  onChanged: (_) async {
                    final ok = await widget.api.toggleCorrelationRule(id);
                    if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                    _load();
                  },
                ),
                title: Text(str(rule['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                subtitle: Text('${str(rule['severity'])} · window: ${str(rule['window_minutes'])}min'),
                trailing: IconButton(
                  icon: const Icon(Icons.delete_outline, color: Colors.redAccent, size: 18),
                  onPressed: () async {
                    if (await xConfirm(context, 'Delete Rule', 'Delete this correlation rule?')) {
                      final ok = await widget.api.deleteCorrelationRule(id);
                      if (context.mounted) xSnack(context, ok ? 'Deleted' : 'Failed', error: !ok);
                      _load();
                    }
                  },
                ),
              ),
            );
          }),
        ],
      ),
    ));
  }

  // Correlation rules support several types (simple/event_count/temporal/
  // temporal_ordered with multi-stage configs) — mobile exposes the
  // simplest real one (event_count: "N matches of rule X within Y minutes")
  // rather than a full stage-builder, matching the established simplified-form
  // precedent for other rule types (Sigma/YARA content is a plain text field too).
  void _createRule() {
    final nameCtrl   = TextEditingController();
    final ruleCtrl   = TextEditingController();
    final windowCtrl = TextEditingController(text: '15');
    final threshCtrl = TextEditingController(text: '3');
    String sev = 'high';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          sheetHeader('New Correlation Rule'),
          xField(nameCtrl, 'Rule Name'),
          const SizedBox(height: 10),
          xField(ruleCtrl, 'Match alert rule_name'),
          const SizedBox(height: 10),
          Row(children: [
            Expanded(child: xField(windowCtrl, 'Window (min)', keyboardType: TextInputType.number)),
            const SizedBox(width: 10),
            Expanded(child: xField(threshCtrl, 'Threshold (>1)', keyboardType: TextInputType.number)),
          ]),
          const SizedBox(height: 10),
          xDropdown('Severity', sev, ['critical','high','medium','low'], (v) => ss(() => sev = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final ok = await widget.api.createCorrelationRule({
                'name': nameCtrl.text.trim(),
                'rule_name': ruleCtrl.text.trim(),
                'severity': sev,
                'correlation_type': 'event_count',
                'source_type': 'alert',
                'window_minutes': int.tryParse(windowCtrl.text) ?? 15,
                'threshold': int.tryParse(threshCtrl.text) ?? 3,
                'enabled': true,
              });
              if (context.mounted) xSnack(context, ok ? 'Rule created' : 'Failed — check window/threshold', error: !ok);
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// ITDR Screen
// ─────────────────────────────────────────────────────────────────────────────

class ITDRScreen extends StatefulWidget {
  final DashboardApi api;
  const ITDRScreen({super.key, required this.api});
  @override State<ITDRScreen> createState() => _ITDRState();
}

class _ITDRState extends State<ITDRScreen> {
  List                 _findings = [];
  bool _loading = true;
  String               _category = '';

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    await Future.wait([
      widget.api.itdrFindings(category: _category).then((r) => _findings = r),
    ]);
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Column(children: [
      FilterRow(
        selected: _category,
        onSelect: (v) { setState(() => _category = v); _load(); },
        chips: const [
          ('All', '', null),
          ('AD', 'active_directory', null),
          ('Cloud', 'cloud', null),
          ('MFA', 'mfa', null),
          ('Priv Esc', 'privilege_escalation', null),
        ],
      ),
      Expanded(child: RefreshIndicator(
        onRefresh: _load,
        child: _findings.isEmpty
          ? const XEmptyState('No ITDR findings', icon: Icons.manage_accounts)
          : ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 0, 12, 80),
              itemCount: _findings.length,
              itemBuilder: (_, i) {
                final f   = _findings[i] as Map<String,dynamic>;
                final id  = f['id'] as int? ?? 0;
                final col = sevColor(str(f['severity']));
                return Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.all(14),
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(10),
                    border: Border.all(color: col.withValues(alpha: .25)),
                    color: col.withValues(alpha: .04)),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Row(children: [
                      Expanded(child: Text(str(f['title'] ?? f['finding_type']),
                        style: const TextStyle(fontSize: 13.5, fontWeight: FontWeight.w700))),
                      SevChip(str(f['severity'])),
                      const SizedBox(width: 6),
                      StatusChip(str(f['status'])),
                    ]),
                    if (f['description'] != null) ...[
                      const SizedBox(height: 6),
                      Text(str(f['description']),
                        style: const TextStyle(fontSize: 12, color: Colors.grey),
                        maxLines: 2, overflow: TextOverflow.ellipsis),
                    ],
                    const SizedBox(height: 8),
                    Row(children: [
                      Text(timeAgo(f['created_at']),
                        style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
                      const Spacer(),
                      TextButton.icon(
                        onPressed: () async {
                          final ok = await widget.api.updateItdrStatus(id, 'acknowledged');
                          if (context.mounted) xSnack(context, ok ? 'Acknowledged' : 'Failed', error: !ok);
                          _load();
                        },
                        icon: const Icon(Icons.check, size: 13),
                        label: const Text('Ack', style: TextStyle(fontSize: 12)),
                        style: TextButton.styleFrom(foregroundColor: const Color(0xFF22C55E)),
                      ),
                    ]),
                  ]),
                );
              },
            ),
      )),
    ]);
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Suppression Rules Screen
// ─────────────────────────────────────────────────────────────────────────────

class SuppressionScreen extends StatefulWidget {
  final DashboardApi api;
  const SuppressionScreen({super.key, required this.api});
  @override State<SuppressionScreen> createState() => _SuppressionState();
}

class _SuppressionState extends State<SuppressionScreen> {
  List _rules   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _rules = await widget.api.suppressionRules();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.add),
        label: const Text('Add Rule'),
      ),
      body: _rules.isEmpty
        ? const XEmptyState('No suppression rules', icon: Icons.volume_off)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
              itemCount: _rules.length,
              itemBuilder: (_, i) {
                // sup_rules: rule_name, status ("draft"|"active"|...),
                // conditions — not name/filter/enabled (a different, older
                // table those keys belonged to).
                final r       = _rules[i] as Map<String,dynamic>;
                final id      = r['id'] as int? ?? 0;
                final enabled = str(r['status']) == 'active';
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Switch(
                      value: enabled,
                      onChanged: (v) async {
                        final ok = await widget.api.updateSuppressionStatus(id, v ? 'active' : 'draft');
                        if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                        _load();
                      },
                    ),
                    title: Text(str(r['rule_name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Text('${str(r['suppression_type'], '')}  ·  ${str(r['conditions'], '')}'),
                    trailing: IconButton(
                      icon: const Icon(Icons.delete_outline, color: Colors.redAccent, size: 18),
                      onPressed: () async {
                        if (await xConfirm(context, 'Delete', 'Delete this suppression rule?')) {
                          final ok = await widget.api.deleteSuppression(id);
                          if (context.mounted) xSnack(context, ok ? 'Deleted' : 'Failed', error: !ok);
                          _load();
                        }
                      },
                    ),
                  ),
                );
              },
            ),
          ),
    );
  }

  void _showCreate() {
    final nameCtrl   = TextEditingController();
    final filterCtrl = TextEditingController();
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('New Suppression Rule'),
            const SizedBox(height: 16),
            xField(nameCtrl,   'Rule Name'),
            const SizedBox(height: 10),
            xField(filterCtrl, 'Conditions (free text)'),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton(
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createSuppressionRule({
                  'rule_name': nameCtrl.text, 'conditions': filterCtrl.text,
                });
                if (context.mounted) xSnack(context, ok ? 'Rule created' : 'Failed', error: !ok);
                _load();
              },
              child: const Text('Create'),
            )),
          ]),
        ),
      ),
    );
  }
}
