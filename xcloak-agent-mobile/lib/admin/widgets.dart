import 'package:flutter/material.dart';

// ── Color helpers ─────────────────────────────────────────────────────────────

Color sevColor(String s) => switch (s.toLowerCase()) {
  'critical' => const Color(0xFFEF4444),
  'high'     => const Color(0xFFF97316),
  'medium'   => const Color(0xFFF59E0B),
  'low'      => const Color(0xFF3B82F6),
  _          => const Color(0xFF6B7280),
};

Color statusColor(String s) => switch (s.toLowerCase()) {
  'open' || 'active' || 'online' || 'enabled' || 'enrolled' => const Color(0xFF22C55E),
  'closed' || 'resolved' || 'offline' || 'inactive'         => const Color(0xFF6B7280),
  'blocked' || 'critical' || 'failed'                        => const Color(0xFFEF4444),
  'pending' || 'investigating' || 'contained'                => const Color(0xFFF97316),
  _                                                          => const Color(0xFF6B7280),
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

  @override
  Widget build(BuildContext context) {
    final c = sevColor(sev);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: c.withOpacity(.12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: c.withOpacity(.35), width: .8),
      ),
      child: Text(
        sev.toUpperCase(),
        style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700, color: c, letterSpacing: .5),
      ),
    );
  }
}

class StatusChip extends StatelessWidget {
  final String status;
  const StatusChip(this.status, {super.key});

  @override
  Widget build(BuildContext context) {
    final c = statusColor(status);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: c.withOpacity(.12),
        borderRadius: BorderRadius.circular(20),
      ),
      child: Text(
        status.toUpperCase(),
        style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600, color: c, letterSpacing: .4),
      ),
    );
  }
}

// ── Pulsing online dot ────────────────────────────────────────────────────────

class OnlineDot extends StatefulWidget {
  final bool online;
  const OnlineDot(this.online, {super.key});
  @override State<OnlineDot> createState() => _OnlineDotState();
}

class _OnlineDotState extends State<OnlineDot> with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;
  late final Animation<double> _scale;
  late final Animation<double> _fade;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 1600))
      ..repeat();
    _scale = Tween(begin: 1.0, end: 2.2).animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeOut));
    _fade  = Tween(begin: .5, end: 0.0).animate(CurvedAnimation(parent: _ctrl, curve: Curves.easeOut));
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    final color = widget.online ? const Color(0xFF22C55E) : const Color(0xFF6B7280);
    if (!widget.online) {
      return Container(width: 9, height: 9,
          decoration: BoxDecoration(shape: BoxShape.circle, color: color));
    }
    return AnimatedBuilder(
      animation: _ctrl,
      builder: (_, __) => SizedBox(width: 16, height: 16,
        child: Stack(alignment: Alignment.center, children: [
          Opacity(
            opacity: _fade.value,
            child: Transform.scale(
              scale: _scale.value,
              child: Container(width: 9, height: 9,
                  decoration: BoxDecoration(shape: BoxShape.circle, color: color)),
            ),
          ),
          Container(width: 9, height: 9,
              decoration: BoxDecoration(shape: BoxShape.circle, color: color)),
        ]),
      ),
    );
  }
}

// ── Empty / Loading ───────────────────────────────────────────────────────────

class XEmptyState extends StatelessWidget {
  final String label;
  final IconData icon;
  const XEmptyState(this.label, {this.icon = Icons.inbox_outlined, super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Center(
      child: Padding(
        padding: const EdgeInsets.all(32),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Container(
            width: 72, height: 72,
            decoration: BoxDecoration(
              color: cs.primary.withOpacity(.07),
              borderRadius: BorderRadius.circular(36),
            ),
            child: Icon(icon, size: 30, color: cs.primary.withOpacity(.45)),
          ),
          const SizedBox(height: 16),
          Text(label,
              style: TextStyle(fontSize: 14, color: cs.onSurface.withOpacity(.45))),
        ]),
      ),
    );
  }
}

Widget xLoading() => Center(
  child: Column(mainAxisSize: MainAxisSize.min, children: [
    const SizedBox(
      width: 28, height: 28,
      child: CircularProgressIndicator(strokeWidth: 2.5),
    ),
    const SizedBox(height: 12),
    Text('Loading…', style: TextStyle(fontSize: 12, color: Colors.grey.shade500)),
  ]),
);

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
      backgroundColor: error ? const Color(0xFFEF4444) : null,
      behavior: SnackBarBehavior.floating,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
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

// ── Stat cards ────────────────────────────────────────────────────────────────

class _StatCard extends StatelessWidget {
  final String label, value;
  final Color color;
  const _StatCard({required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 14),
        child: Row(children: [
          Container(
            width: 4,
            height: 36,
            decoration: BoxDecoration(
              color: color,
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          const SizedBox(width: 10),
          Expanded(
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisSize: MainAxisSize.min, children: [
              Text(value,
                  style: TextStyle(fontSize: 22, fontWeight: FontWeight.w700, color: color, height: 1.1)),
              const SizedBox(height: 2),
              Text(label,
                  style: TextStyle(fontSize: 10, color: Theme.of(context).colorScheme.onSurface.withOpacity(.5), letterSpacing: .2),
                  maxLines: 1, overflow: TextOverflow.ellipsis),
            ]),
          ),
        ]),
      ),
    );
  }
}

class StatRow extends StatelessWidget {
  final List<(String, String, Color)> stats;
  const StatRow(this.stats, {super.key});

  @override
  Widget build(BuildContext context) => Row(
    children: stats.map((s) => Expanded(
      child: Padding(
        padding: const EdgeInsets.all(4),
        child: _StatCard(label: s.$1, value: s.$2, color: s.$3),
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
      decoration: InputDecoration(labelText: label),
    );

DropdownButtonFormField<String> xDropdown(String label, String value, List<String> items, void Function(String?) onChanged) =>
    DropdownButtonFormField<String>(
      value: items.contains(value) ? value : items.first,
      decoration: InputDecoration(labelText: label),
      items: items.map((i) => DropdownMenuItem(value: i, child: Text(i))).toList(),
      onChanged: onChanged,
    );

Widget sheetHeader(String title) => Column(children: [
  Container(
    width: 36, height: 4,
    decoration: BoxDecoration(color: Colors.grey.shade300, borderRadius: BorderRadius.circular(2)),
  ),
  const SizedBox(height: 14),
  Text(title, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700)),
  const SizedBox(height: 16),
]);

// ── Detail sheet ──────────────────────────────────────────────────────────────

void showDetailSheet(BuildContext context, String title, List<(String, String)> rows, {List<Widget>? actions}) {
  final cs = Theme.of(context).colorScheme;
  showModalBottomSheet(
    context: context,
    isScrollControlled: true,
    shape: const RoundedRectangleBorder(
      borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
    ),
    builder: (_) => DraggableScrollableSheet(
      initialChildSize: 0.6,
      minChildSize: 0.3,
      maxChildSize: 0.95,
      expand: false,
      builder: (_, ctrl) => Column(
        children: [
          const SizedBox(height: 10),
          Container(
            width: 36, height: 4,
            decoration: BoxDecoration(
              color: cs.onSurface.withOpacity(.2),
              borderRadius: BorderRadius.circular(2),
            ),
          ),
          Padding(
            padding: const EdgeInsets.fromLTRB(20, 14, 12, 14),
            child: Row(children: [
              Expanded(child: Text(title,
                  style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700))),
              if (actions != null) ...actions,
            ]),
          ),
          Divider(height: 1, color: cs.outline.withOpacity(.2)),
          Expanded(
            child: ListView(
              controller: ctrl,
              padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
              children: rows.map((r) => Padding(
                padding: const EdgeInsets.only(bottom: 12),
                child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  SizedBox(
                    width: 110,
                    child: Text(r.$1,
                        style: TextStyle(fontSize: 12, color: cs.onSurface.withOpacity(.5))),
                  ),
                  Expanded(child: Text(r.$2,
                      style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w500))),
                ]),
              )).toList(),
            ),
          ),
        ],
      ),
    ),
  );
}
