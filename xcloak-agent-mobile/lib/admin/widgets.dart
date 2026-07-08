import 'dart:math';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';

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
        color: c.withValues(alpha: .12),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: c.withValues(alpha: .35), width: .8),
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
        color: c.withValues(alpha: .12),
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
              color: cs.primary.withValues(alpha: .07),
              borderRadius: BorderRadius.circular(36),
            ),
            child: Icon(icon, size: 30, color: cs.primary.withValues(alpha: .45)),
          ),
          const SizedBox(height: 16),
          Text(label,
              style: TextStyle(fontSize: 14, color: cs.onSurface.withValues(alpha: .45))),
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
                  style: TextStyle(fontSize: 10, color: Theme.of(context).colorScheme.onSurface.withValues(alpha: .5), letterSpacing: .2),
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

// ── KPI card ──────────────────────────────────────────────────────────────────

class KpiCard extends StatelessWidget {
  final String label, value;
  final Color  color;
  final IconData icon;
  final String? trend;   // e.g. '+12%' or '-5%' — null = no trend
  final VoidCallback? onTap;
  const KpiCard({required this.label, required this.value, required this.color,
    required this.icon, this.trend, this.onTap, super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.fromLTRB(14, 12, 12, 12),
        decoration: BoxDecoration(
          color: cs.surfaceContainerLow,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(color: color.withValues(alpha: .2)),
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Row(children: [
            Container(
              width: 30, height: 30,
              decoration: BoxDecoration(
                color: color.withValues(alpha: .12),
                borderRadius: BorderRadius.circular(8)),
              child: Icon(icon, color: color, size: 16),
            ),
            const Spacer(),
            if (trend != null)
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: (trend!.startsWith('-') ? const Color(0xFF22C55E) : const Color(0xFFEF4444)).withValues(alpha: .12),
                  borderRadius: BorderRadius.circular(6)),
                child: Text(trend!,
                  style: TextStyle(fontSize: 9.5, fontWeight: FontWeight.w700,
                    color: trend!.startsWith('-') ? const Color(0xFF22C55E) : const Color(0xFFEF4444))),
              ),
          ]),
          const SizedBox(height: 8),
          Text(value, style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: color, height: 1)),
          const SizedBox(height: 2),
          Text(label, style: TextStyle(fontSize: 10.5, color: cs.onSurface.withValues(alpha: .5), letterSpacing: .1),
            maxLines: 1, overflow: TextOverflow.ellipsis),
        ]),
      ),
    );
  }
}

// ── Section title ─────────────────────────────────────────────────────────────

class SectionTitle extends StatelessWidget {
  final String text;
  final Widget? trailing;
  const SectionTitle(this.text, {this.trailing, super.key});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 10),
    child: Row(children: [
      Container(width: 3, height: 14,
        decoration: BoxDecoration(
          color: Theme.of(context).colorScheme.primary,
          borderRadius: BorderRadius.circular(2))),
      const SizedBox(width: 8),
      Text(text, style: TextStyle(fontSize: 11.5, fontWeight: FontWeight.w800,
        letterSpacing: .8, color: Theme.of(context).colorScheme.onSurface.withValues(alpha: .65))),
      if (trailing != null) ...[const Spacer(), trailing!],
    ]),
  );
}

// ── Ring gauge ────────────────────────────────────────────────────────────────

class RingGauge extends StatelessWidget {
  final double value;   // 0.0–1.0
  final Color  color;
  final double size;
  final String label;
  final String sublabel;
  const RingGauge({required this.value, required this.color, this.size = 80,
    this.label = '', this.sublabel = '', super.key});

  @override
  Widget build(BuildContext context) => SizedBox(
    width: size, height: size,
    child: CustomPaint(
      painter: _RingGaugePainter(value: value.clamp(0.0, 1.0), color: color),
      child: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
        if (label.isNotEmpty)
          Text(label, style: TextStyle(fontSize: size * .22,
            fontWeight: FontWeight.w900, color: color, height: 1.1)),
        if (sublabel.isNotEmpty)
          Text(sublabel, style: TextStyle(fontSize: size * .13, color: Colors.grey)),
      ])),
    ),
  );
}

class _RingGaugePainter extends CustomPainter {
  final double value;
  final Color  color;
  const _RingGaugePainter({required this.value, required this.color});

  @override
  void paint(Canvas canvas, Size size) {
    const sw = 7.0;
    final r    = min(size.width, size.height) / 2 - sw / 2;
    final rect = Rect.fromCircle(center: Offset(size.width / 2, size.height / 2), radius: r);
    canvas.drawArc(rect, -pi / 2, 2 * pi, false, Paint()
      ..color       = color.withValues(alpha: .13)
      ..style       = PaintingStyle.stroke
      ..strokeWidth = sw
      ..strokeCap   = StrokeCap.round);
    if (value > 0) {
      canvas.drawArc(rect, -pi / 2, 2 * pi * value, false, Paint()
        ..color       = color
        ..style       = PaintingStyle.stroke
        ..strokeWidth = sw
        ..strokeCap   = StrokeCap.round);
    }
  }

  @override
  bool shouldRepaint(_RingGaugePainter old) => old.value != value || old.color != color;
}

// ── Typing indicator (animated 3 dots) ───────────────────────────────────────

class TypingIndicator extends StatefulWidget {
  const TypingIndicator({super.key});
  @override State<TypingIndicator> createState() => _TypingIndicatorState();
}

class _TypingIndicatorState extends State<TypingIndicator> with SingleTickerProviderStateMixin {
  late final AnimationController _ctrl;

  @override
  void initState() {
    super.initState();
    _ctrl = AnimationController(vsync: this, duration: const Duration(milliseconds: 900))..repeat();
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => AnimatedBuilder(
    animation: _ctrl,
    builder: (_, __) => Row(mainAxisSize: MainAxisSize.min, children: List.generate(3, (i) {
      final t = ((_ctrl.value * 3 - i) % 3).clamp(0.0, 1.0);
      return Container(
        width: 7, height: 7,
        margin: const EdgeInsets.only(right: 4),
        decoration: BoxDecoration(
          color: Colors.grey.withValues(alpha: .3 + t * .5),
          shape: BoxShape.circle),
      );
    })),
  );
}

// ── Info pair ─────────────────────────────────────────────────────────────────

class InfoPair extends StatelessWidget {
  final String label, value;
  final Color? valueColor;
  const InfoPair(this.label, this.value, {this.valueColor, super.key});

  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 7),
    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
      SizedBox(width: 110, child: Text(label,
        style: TextStyle(fontSize: 12, color: Colors.grey.shade500))),
      Expanded(child: Text(value,
        style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600, color: valueColor))),
    ]),
  );
}

// ── Health bar ────────────────────────────────────────────────────────────────

class HealthBar extends StatelessWidget {
  final int score;
  const HealthBar(this.score, {super.key});

  Color get _color {
    if (score >= 80) return const Color(0xFF22C55E);
    if (score >= 55) return const Color(0xFFF59E0B);
    return const Color(0xFFEF4444);
  }

  @override
  Widget build(BuildContext context) => Column(
    crossAxisAlignment: CrossAxisAlignment.start,
    mainAxisSize: MainAxisSize.min,
    children: [
      Row(children: [
        Expanded(child: ClipRRect(
          borderRadius: BorderRadius.circular(3),
          child: LinearProgressIndicator(
            value: score / 100, minHeight: 4,
            backgroundColor: _color.withValues(alpha: .15),
            valueColor: AlwaysStoppedAnimation(_color)),
        )),
        const SizedBox(width: 6),
        Text('$score', style: TextStyle(fontSize: 10.5, fontWeight: FontWeight.w700, color: _color)),
      ]),
    ],
  );
}

// ── Bulk action bar ───────────────────────────────────────────────────────────

class BulkBar extends StatelessWidget {
  final int count;
  final List<(IconData, String, VoidCallback)> actions;
  final VoidCallback onCancel;
  const BulkBar({required this.count, required this.actions, required this.onCancel, super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      color: cs.primaryContainer,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
      child: Row(children: [
        IconButton(onPressed: onCancel, icon: const Icon(Icons.close), padding: EdgeInsets.zero),
        Text('$count selected', style: TextStyle(fontWeight: FontWeight.w700, color: cs.onPrimaryContainer)),
        const Spacer(),
        ...actions.map((a) => IconButton(
          icon: Icon(a.$1), tooltip: a.$2, onPressed: a.$3,
          style: IconButton.styleFrom(foregroundColor: cs.onPrimaryContainer),
        )),
      ]),
    );
  }
}

// ── Filter chip row ───────────────────────────────────────────────────────────

class FilterRow extends StatelessWidget {
  final List<(String label, String value, int? count)> chips;
  final String selected;
  final void Function(String) onSelect;
  const FilterRow({required this.chips, required this.selected, required this.onSelect, super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      child: Row(children: chips.map((c) {
        final active = selected == c.$2;
        return Padding(
          padding: const EdgeInsets.only(right: 6),
          child: GestureDetector(
            onTap: () => onSelect(c.$2),
            child: AnimatedContainer(
              duration: const Duration(milliseconds: 160),
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: active ? cs.primary : cs.surfaceContainerLow,
                borderRadius: BorderRadius.circular(20),
                border: Border.all(color: active ? cs.primary : cs.outlineVariant)),
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                Text(c.$1, style: TextStyle(fontSize: 12.5, fontWeight: FontWeight.w600,
                  color: active ? cs.onPrimary : cs.onSurface)),
                if (c.$3 != null) ...[
                  const SizedBox(width: 5),
                  Container(
                    padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1),
                    decoration: BoxDecoration(
                      color: active ? cs.onPrimary.withValues(alpha: .2) : cs.outline.withValues(alpha: .3),
                      borderRadius: BorderRadius.circular(10)),
                    child: Text('${c.$3}',
                      style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800,
                        color: active ? cs.onPrimary : cs.onSurface)),
                  ),
                ],
              ]),
            ),
          ),
        );
      }).toList()),
    );
  }
}

// ── Timeline entry ────────────────────────────────────────────────────────────

class TimelineEntry extends StatelessWidget {
  final IconData icon;
  final Color    color;
  final String   title, subtitle, time;
  final bool     isLast;
  const TimelineEntry({required this.icon, required this.color, required this.title,
    required this.subtitle, required this.time, this.isLast = false, super.key});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return IntrinsicHeight(
      child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        SizedBox(width: 40, child: Column(children: [
          Container(width: 32, height: 32,
            decoration: BoxDecoration(color: color.withValues(alpha: .12), shape: BoxShape.circle),
            child: Icon(icon, size: 15, color: color)),
          if (!isLast) Expanded(child: Container(width: 1.5,
            color: cs.outlineVariant.withValues(alpha: .5))),
        ])),
        Expanded(child: Padding(
          padding: EdgeInsets.only(left: 10, bottom: isLast ? 0 : 14),
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(title,
                style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w600))),
              Text(time, style: const TextStyle(fontSize: 10.5, color: Colors.grey)),
            ]),
            if (subtitle.isNotEmpty)
              Text(subtitle, style: const TextStyle(fontSize: 11.5, color: Colors.grey),
                maxLines: 2, overflow: TextOverflow.ellipsis),
          ]),
        )),
      ]),
    );
  }
}

// ── Swipe action card wrapper ─────────────────────────────────────────────────

Widget swipeCard({
  required Widget child,
  required int key,
  required String rightLabel,
  required Color  rightColor,
  required IconData rightIcon,
  required String leftLabel,
  required Color  leftColor,
  required IconData leftIcon,
  required VoidCallback onRight,
  required VoidCallback onLeft,
}) => Dismissible(
  key: Key('swipe_$key'),
  confirmDismiss: (dir) async {
    if (dir == DismissDirection.startToEnd) onRight();
    else onLeft();
    return false;  // keep in list; screen reloads after action
  },
  background: Container(
    alignment: Alignment.centerLeft,
    padding: const EdgeInsets.only(left: 20),
    margin: const EdgeInsets.only(bottom: 8),
    decoration: BoxDecoration(color: rightColor.withValues(alpha: .15),
      borderRadius: BorderRadius.circular(12)),
    child: Row(children: [
      Icon(rightIcon, color: rightColor),
      const SizedBox(width: 6),
      Text(rightLabel, style: TextStyle(color: rightColor, fontWeight: FontWeight.w700)),
    ]),
  ),
  secondaryBackground: Container(
    alignment: Alignment.centerRight,
    padding: const EdgeInsets.only(right: 20),
    margin: const EdgeInsets.only(bottom: 8),
    decoration: BoxDecoration(color: leftColor.withValues(alpha: .15),
      borderRadius: BorderRadius.circular(12)),
    child: Row(children: [
      const Spacer(),
      Text(leftLabel, style: TextStyle(color: leftColor, fontWeight: FontWeight.w700)),
      const SizedBox(width: 6),
      Icon(leftIcon, color: leftColor),
    ]),
  ),
  child: child,
);

// ── Copy to clipboard helper ──────────────────────────────────────────────────

void copyToClipboard(BuildContext context, String text) {
  Clipboard.setData(ClipboardData(text: text));
  xSnack(context, 'Copied to clipboard');
}

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
              color: cs.onSurface.withValues(alpha: .2),
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
          Divider(height: 1, color: cs.outline.withValues(alpha: .2)),
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
                        style: TextStyle(fontSize: 12, color: cs.onSurface.withValues(alpha: .5))),
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
