import 'package:flutter/material.dart';

// ── Color helpers ─────────────────────────────────────────────────────────────

Color sevColor(String s) => switch (s.toLowerCase()) {
  'critical' => Colors.red,
  'high'     => Colors.orange,
  'medium'   => Colors.yellow.shade700,
  'low'      => Colors.blue,
  _          => Colors.grey,
};

Color statusColor(String s) => switch (s.toLowerCase()) {
  'open' || 'active' || 'online' || 'enabled' || 'enrolled' => Colors.green,
  'closed' || 'resolved' || 'offline' || 'inactive'         => Colors.grey,
  'blocked' || 'critical' || 'failed'                        => Colors.red,
  'pending' || 'investigating' || 'contained'                => Colors.orange,
  _                                                          => Colors.grey,
};

String timeAgo(dynamic ts) {
  if (ts == null) return '—';
  final s = ts.toString();
  if (s.isEmpty) return '—';
  try {
    final d    = DateTime.parse(s).toLocal();
    final diff = DateTime.now().difference(d);
    if (diff.inSeconds < 60)  return 'just now';
    if (diff.inMinutes < 60)  return '${diff.inMinutes}m ago';
    if (diff.inHours < 24)    return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  } catch (_) { return s; }
}

String str(dynamic v, [String fallback = '—']) =>
    (v == null || v.toString().isEmpty) ? fallback : v.toString();

// ── Chips ─────────────────────────────────────────────────────────────────────

class SevChip extends StatelessWidget {
  final String sev;
  const SevChip(this.sev, {super.key});
  @override Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
    decoration: BoxDecoration(
      color: sevColor(sev).withOpacity(.18),
      borderRadius: BorderRadius.circular(4),
      border: Border.all(color: sevColor(sev).withOpacity(.5)),
    ),
    child: Text(sev.toUpperCase(), style: TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: sevColor(sev))),
  );
}

class StatusChip extends StatelessWidget {
  final String status;
  const StatusChip(this.status, {super.key});
  @override Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
    decoration: BoxDecoration(
      color: statusColor(status).withOpacity(.15),
      borderRadius: BorderRadius.circular(4),
    ),
    child: Text(status.toUpperCase(), style: TextStyle(fontSize: 10, color: statusColor(status))),
  );
}

class OnlineDot extends StatelessWidget {
  final bool online;
  const OnlineDot(this.online, {super.key});
  @override Widget build(BuildContext context) => Container(
    width: 8, height: 8,
    decoration: BoxDecoration(
      shape: BoxShape.circle,
      color: online ? Colors.green : Colors.grey,
    ),
  );
}

// ── Empty / Loading ───────────────────────────────────────────────────────────

class XEmptyState extends StatelessWidget {
  final String label;
  const XEmptyState(this.label, {super.key});
  @override Widget build(BuildContext context) => Center(
    child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      Icon(Icons.inbox_outlined, size: 48, color: Colors.grey.shade600),
      const SizedBox(height: 12),
      Text(label, style: TextStyle(color: Colors.grey.shade500)),
    ]),
  );
}

Widget xLoading() => const Center(child: CircularProgressIndicator());

// ── Confirm dialog ────────────────────────────────────────────────────────────

Future<bool> xConfirm(BuildContext context, String title, String body) async =>
    await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Text(title),
        content: Text(body),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('Delete', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    ) ?? false;

// ── Snackbar ──────────────────────────────────────────────────────────────────

void xSnack(BuildContext context, String msg, {bool error = false}) =>
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: error ? Colors.red : null,
      duration: const Duration(seconds: 2),
    ));

// ── Section scaffold ──────────────────────────────────────────────────────────

class XSection extends StatelessWidget {
  final bool loading;
  final Future<void> Function() onRefresh;
  final Widget child;
  final List<Widget>? actions;
  final Widget? fab;

  const XSection({
    super.key,
    required this.loading,
    required this.onRefresh,
    required this.child,
    this.actions,
    this.fab,
  });

  @override
  Widget build(BuildContext context) {
    if (loading) return xLoading();
    return Scaffold(
      body: RefreshIndicator(onRefresh: onRefresh, child: child),
      floatingActionButton: fab,
    );
  }
}

// ── Simple stat row ───────────────────────────────────────────────────────────

class StatRow extends StatelessWidget {
  final List<(String, String, Color)> stats;
  const StatRow(this.stats, {super.key});

  @override
  Widget build(BuildContext context) => Row(
    children: stats.map((s) => Expanded(
      child: Card(
        margin: const EdgeInsets.all(4),
        child: Padding(
          padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
          child: Column(
            children: [
              Text(s.$2, style: TextStyle(fontSize: 20, fontWeight: FontWeight.bold, color: s.$3)),
              Text(s.$1, style: const TextStyle(fontSize: 10, color: Colors.grey), textAlign: TextAlign.center),
            ],
          ),
        ),
      ),
    )).toList(),
  );
}

// ── Bottom sheet form helpers ─────────────────────────────────────────────────

TextField xField(TextEditingController ctrl, String label, {int maxLines = 1, bool obscure = false, TextInputType? keyboardType}) =>
    TextField(
      controller: ctrl,
      maxLines: maxLines,
      obscureText: obscure,
      keyboardType: keyboardType,
      decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
    );

DropdownButtonFormField<String> xDropdown(String label, String value, List<String> items, void Function(String?) onChanged) =>
    DropdownButtonFormField<String>(
      value: items.contains(value) ? value : items.first,
      decoration: InputDecoration(labelText: label, border: const OutlineInputBorder()),
      items: items.map((i) => DropdownMenuItem(value: i, child: Text(i))).toList(),
      onChanged: onChanged,
    );

// ── Detail sheet ──────────────────────────────────────────────────────────────

void showDetailSheet(BuildContext context, String title, List<(String, String)> rows, {List<Widget>? actions}) {
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    builder: (_) => DraggableScrollableSheet(
      initialChildSize: 0.6,
      minChildSize: 0.3,
      maxChildSize: 0.95,
      expand: false,
      builder: (_, ctrl) => Column(
        children: [
          const SizedBox(height: 8),
          Container(width: 40, height: 4, decoration: BoxDecoration(color: Colors.grey.shade400, borderRadius: BorderRadius.circular(2))),
          Padding(
            padding: const EdgeInsets.all(16),
            child: Row(children: [
              Expanded(child: Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.bold))),
              if (actions != null) ...actions,
            ]),
          ),
          const Divider(height: 1),
          Expanded(
            child: ListView(
              controller: ctrl,
              padding: const EdgeInsets.all(12),
              children: rows.map((r) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  SizedBox(width: 120, child: Text(r.$1, style: const TextStyle(color: Colors.grey, fontSize: 12))),
                  Expanded(child: Text(r.$2, style: const TextStyle(fontSize: 13))),
                ]),
              )).toList(),
            ),
          ),
        ],
      ),
    ),
  );
}
