import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ─────────────────────────────────────────────────────────────────────────────
// AI Security Assistant
// ─────────────────────────────────────────────────────────────────────────────

const _kSuggestedPrompts = [
  ('Summarize today\'s threats', Icons.summarize),
  ('Top 5 critical alerts', Icons.priority_high),
  ('Explain MITRE ATT&CK T1059', Icons.school),
  ('What\'s the risk posture?', Icons.shield),
  ('Agents with most alerts', Icons.computer),
  ('Unusual network activity?', Icons.lan),
  ('Recommend remediation steps', Icons.healing),
  ('Draft incident report', Icons.description),
];

class AIAssistantScreen extends StatefulWidget {
  final DashboardApi api;
  const AIAssistantScreen({super.key, required this.api});
  @override State<AIAssistantScreen> createState() => _AIAssistantState();
}

class _AIAssistantState extends State<AIAssistantScreen> {
  final List<_Msg>         _messages   = [];
  final TextEditingController _ctrl     = TextEditingController();
  final ScrollController   _scroll     = ScrollController();
  bool   _sending   = false;
  bool   _loadingHistory = true;
  String? _sessionId;

  @override
  void initState() {
    super.initState();
    _loadHistory();
  }

  @override
  void dispose() {
    _ctrl.dispose();
    _scroll.dispose();
    super.dispose();
  }

  Future<void> _loadHistory() async {
    setState(() => _loadingHistory = true);
    final history = await widget.api.chatHistory();
    if (!mounted) return;
    _messages.clear();
    for (final m in history) {
      final map  = m as Map<String,dynamic>;
      final role = str(map['role'] ?? map['sender']);
      final text = str(map['content'] ?? map['message']);
      if (text.isNotEmpty) _messages.add(_Msg(text: text, isUser: role == 'user'));
    }
    setState(() => _loadingHistory = false);
    _scrollBottom();
  }

  Future<void> _send(String text) async {
    final trimmed = text.trim();
    if (trimmed.isEmpty || _sending) return;
    _ctrl.clear();
    setState(() {
      _messages.add(_Msg(text: trimmed, isUser: true));
      _sending = true;
    });
    _scrollBottom();

    final res = await widget.api.aiChat(trimmed, sessionId: _sessionId);
    if (!mounted) return;

    final reply = str(res?['response'] ?? res?['message'] ?? res?['content'] ?? '');
    _sessionId ??= str(res?['session_id']);

    setState(() {
      _sending = false;
      if (reply.isNotEmpty) _messages.add(_Msg(text: reply, isUser: false));
    });
    _scrollBottom();
  }

  void _scrollBottom() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) {
        _scroll.animateTo(_scroll.position.maxScrollExtent,
          duration: const Duration(milliseconds: 250), curve: Curves.easeOut);
      }
    });
  }

  Future<void> _clearHistory() async {
    if (!await xConfirm(context, 'Clear History', 'Delete all chat history?')) return;
    await widget.api.clearChatHistory();
    if (!mounted) return;
    setState(() { _messages.clear(); _sessionId = null; });
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    if (_loadingHistory) return xLoading();

    return Column(children: [
      // Clear + session badge
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 6, 8, 0),
        child: Row(children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: const Color(0xFF6366F1).withValues(alpha: .1),
              borderRadius: BorderRadius.circular(20)),
            child: Row(mainAxisSize: MainAxisSize.min, children: [
              const Icon(Icons.psychology, size: 13, color: Color(0xFF6366F1)),
              const SizedBox(width: 5),
              Text('XCloak AI', style: const TextStyle(
                fontSize: 11.5, fontWeight: FontWeight.w700, color: Color(0xFF6366F1))),
            ]),
          ),
          const Spacer(),
          if (_messages.isNotEmpty)
            TextButton.icon(
              onPressed: _clearHistory,
              icon: const Icon(Icons.delete_sweep, size: 14),
              label: const Text('Clear', style: TextStyle(fontSize: 12)),
              style: TextButton.styleFrom(foregroundColor: Colors.grey),
            ),
        ]),
      ),

      // Message list
      Expanded(child: _messages.isEmpty
        ? _EmptyChat(onPrompt: _send)
        : ListView.builder(
            controller: _scroll,
            padding: const EdgeInsets.fromLTRB(12, 8, 12, 12),
            itemCount: _messages.length + (_sending ? 1 : 0),
            itemBuilder: (_, i) {
              if (i == _messages.length) {
                return const Align(
                  alignment: Alignment.centerLeft,
                  child: _AiBubble(child: TypingIndicator()),
                );
              }
              return _BubbleTile(msg: _messages[i]);
            },
          )),

      // Input bar
      SafeArea(child: Padding(
        padding: EdgeInsets.only(
          left: 12, right: 12, bottom: 12,
          top: MediaQuery.of(context).viewInsets.bottom > 0 ? 4 : 6),
        child: Row(children: [
          Expanded(child: TextField(
            controller: _ctrl,
            minLines: 1, maxLines: 4,
            textInputAction: TextInputAction.send,
            onSubmitted: _send,
            decoration: InputDecoration(
              hintText: 'Ask the SOC AI anything…',
              hintStyle: const TextStyle(fontSize: 13),
              isDense: true,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              border: OutlineInputBorder(borderRadius: BorderRadius.circular(22)),
              filled: true,
              fillColor: cs.surfaceContainerLow,
            ),
          )),
          const SizedBox(width: 8),
          FilledButton(
            onPressed: _sending ? null : () => _send(_ctrl.text),
            style: FilledButton.styleFrom(
              shape: const CircleBorder(),
              padding: const EdgeInsets.all(14),
              backgroundColor: const Color(0xFF6366F1),
            ),
            child: _sending
              ? const SizedBox(width: 18, height: 18, child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
              : const Icon(Icons.send, size: 18, color: Colors.white),
          ),
        ]),
      )),
    ]);
  }
}

class _EmptyChat extends StatelessWidget {
  final void Function(String) onPrompt;
  const _EmptyChat({required this.onPrompt});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return ListView(
      padding: const EdgeInsets.all(20),
      children: [
        const SizedBox(height: 12),
        Center(child: Container(
          width: 64, height: 64,
          decoration: BoxDecoration(
            color: const Color(0xFF6366F1).withValues(alpha: .12),
            shape: BoxShape.circle),
          child: const Icon(Icons.psychology, size: 34, color: Color(0xFF6366F1)),
        )),
        const SizedBox(height: 16),
        const Center(child: Text('XCloak Security AI',
          style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800))),
        const SizedBox(height: 6),
        Center(child: Text('Ask about threats, get recommendations, investigate incidents',
          style: TextStyle(fontSize: 13, color: Colors.grey.shade500),
          textAlign: TextAlign.center)),
        const SizedBox(height: 28),
        Text('Suggested', style: TextStyle(fontSize: 11, letterSpacing: .8,
          fontWeight: FontWeight.w700, color: Colors.grey.shade500)),
        const SizedBox(height: 12),
        Wrap(spacing: 8, runSpacing: 8, children: _kSuggestedPrompts.map((p) =>
          ActionChip(
            avatar: Icon(p.$2, size: 14),
            label: Text(p.$1, style: const TextStyle(fontSize: 12.5)),
            onPressed: () => onPrompt(p.$1),
            backgroundColor: cs.surfaceContainerLow,
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(20)),
          )
        ).toList()),
      ],
    );
  }
}

class _BubbleTile extends StatelessWidget {
  final _Msg msg;
  const _BubbleTile({required this.msg});

  @override
  Widget build(BuildContext context) {
    if (msg.isUser) {
      return Align(
        alignment: Alignment.centerRight,
        child: Container(
          margin: const EdgeInsets.only(bottom: 10, left: 60),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          decoration: BoxDecoration(
            color: const Color(0xFF6366F1),
            borderRadius: const BorderRadius.only(
              topLeft: Radius.circular(16), topRight: Radius.circular(16),
              bottomLeft: Radius.circular(16), bottomRight: Radius.circular(4))),
          child: SelectableText(msg.text,
            style: const TextStyle(fontSize: 13.5, color: Colors.white, height: 1.45)),
        ),
      );
    }
    return Align(
      alignment: Alignment.centerLeft,
      child: _AiBubble(
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          SelectableText(msg.text,
            style: const TextStyle(fontSize: 13.5, height: 1.45)),
          const SizedBox(height: 6),
          Row(mainAxisSize: MainAxisSize.min, children: [
            GestureDetector(
              onTap: () => copyToClipboard(context, msg.text),
              child: const Icon(Icons.copy, size: 13, color: Colors.grey),
            ),
          ]),
        ]),
      ),
    );
  }
}

class _AiBubble extends StatelessWidget {
  final Widget child;
  const _AiBubble({required this.child});

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;
    return Container(
      margin: const EdgeInsets.only(bottom: 10, right: 60),
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color: cs.surfaceContainerLow,
        borderRadius: const BorderRadius.only(
          topLeft: Radius.circular(4), topRight: Radius.circular(16),
          bottomLeft: Radius.circular(16), bottomRight: Radius.circular(16))),
      child: child,
    );
  }
}

class _Msg {
  final String text;
  final bool isUser;
  const _Msg({required this.text, required this.isUser});
}

// ─────────────────────────────────────────────────────────────────────────────
// Settings — tabbed: Users, API Keys, Integrations, Roles
// ─────────────────────────────────────────────────────────────────────────────

class SettingsScreen extends StatefulWidget {
  final DashboardApi api;
  const SettingsScreen({super.key, required this.api});
  @override State<SettingsScreen> createState() => _SettingsState();
}

class _SettingsState extends State<SettingsScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;

  @override
  void initState() {
    super.initState();
    _tabs = TabController(length: 4, vsync: this);
  }

  @override void dispose() { _tabs.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => Column(children: [
    TabBar(
      controller: _tabs,
      labelStyle: const TextStyle(fontSize: 12, fontWeight: FontWeight.w700),
      tabs: const [Tab(text: 'Users'), Tab(text: 'API Keys'), Tab(text: 'Integrations'), Tab(text: 'Roles')],
    ),
    Expanded(child: TabBarView(controller: _tabs, children: [
      _UsersTab(api: widget.api),
      _ApiKeysTab(api: widget.api),
      _IntegrationsTab(api: widget.api),
      _RolesTab(api: widget.api),
    ])),
  ]);
}

// ── Users tab ─────────────────────────────────────────────────────────────────

class _UsersTab extends StatefulWidget {
  final DashboardApi api;
  const _UsersTab({required this.api});
  @override State<_UsersTab> createState() => _UsersTabState();
}

class _UsersTabState extends State<_UsersTab> with AutomaticKeepAliveClientMixin {
  @override bool get wantKeepAlive => true;
  List _users   = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _users = await widget.api.users();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showInvite,
        icon: const Icon(Icons.person_add),
        label: const Text('Invite'),
      ),
      body: _users.isEmpty
        ? const XEmptyState('No users', icon: Icons.people_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
              itemCount: _users.length,
              itemBuilder: (_, i) {
                final u   = _users[i] as Map<String,dynamic>;
                final id  = u['id'] as int? ?? 0;
                final active = u['is_active'] != false;
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: CircleAvatar(
                      backgroundColor: active
                        ? const Color(0xFF6366F1).withValues(alpha: .12)
                        : Colors.grey.withValues(alpha: .12),
                      child: Text((str(u['email'], 'U')[0]).toUpperCase(),
                        style: TextStyle(
                          color: active ? const Color(0xFF6366F1) : Colors.grey,
                          fontWeight: FontWeight.w800)),
                    ),
                    title: Text(str(u['email']), style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Row(children: [
                      StatusChip(active ? 'active' : 'disabled'),
                      const SizedBox(width: 6),
                      Text(str(u['role']), style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
                    ]),
                    trailing: PopupMenuButton<String>(
                      onSelected: (action) async {
                        if (action == 'toggle') {
                          final ok = await widget.api.toggleUser(id);
                          if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                          _load();
                        } else if (action == 'reset') {
                          final ok = await widget.api.resetUserPassword(id);
                          if (context.mounted) xSnack(context, ok ? 'Reset link sent' : 'Failed', error: !ok);
                        } else if (action == 'delete') {
                          if (!context.mounted) return;
                          if (await xConfirm(context, 'Delete User', 'Delete this user permanently?')) {
                            final ok = await widget.api.deleteUser(id);
                            if (context.mounted) xSnack(context, ok ? 'Deleted' : 'Failed', error: !ok);
                            _load();
                          }
                        }
                      },
                      itemBuilder: (_) => [
                        PopupMenuItem(value: 'toggle',
                          child: Text(active ? 'Disable' : 'Enable')),
                        const PopupMenuItem(value: 'reset',
                          child: Text('Reset Password')),
                        const PopupMenuDivider(),
                        const PopupMenuItem(value: 'delete',
                          child: Text('Delete', style: TextStyle(color: Colors.redAccent))),
                      ],
                    ),
                  ),
                );
              },
            ),
          ),
    );
  }

  void _showInvite() {
    final emailCtrl = TextEditingController();
    String role     = 'analyst';
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('Invite User'),
            const SizedBox(height: 16),
            xField(emailCtrl, 'Email address'),
            const SizedBox(height: 12),
            xDropdown('Role', role, const ['analyst', 'admin', 'viewer'], (v) => ss(() => role = v!)),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.send, size: 16),
              label: const Text('Send Invite'),
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.inviteUser(emailCtrl.text, role);
                if (context.mounted) xSnack(context, ok ? 'Invite sent' : 'Failed', error: !ok);
                _load();
              },
            )),
          ]),
        ),
      )),
    );
  }
}

// ── API Keys tab ──────────────────────────────────────────────────────────────

class _ApiKeysTab extends StatefulWidget {
  final DashboardApi api;
  const _ApiKeysTab({required this.api});
  @override State<_ApiKeysTab> createState() => _ApiKeysTabState();
}

class _ApiKeysTabState extends State<_ApiKeysTab> with AutomaticKeepAliveClientMixin {
  @override bool get wantKeepAlive => true;
  List   _keys    = [];
  bool   _loading = true;
  String? _newKeyValue;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _keys = await widget.api.apiKeys();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.vpn_key),
        label: const Text('New Key'),
      ),
      body: Column(children: [
        if (_newKeyValue != null)
          Container(
            margin: const EdgeInsets.all(12),
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0xFF22C55E).withValues(alpha: .07),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(color: const Color(0xFF22C55E).withValues(alpha: .25))),
            child: Row(children: [
              const Icon(Icons.vpn_key, color: Color(0xFF22C55E), size: 16),
              const SizedBox(width: 8),
              Expanded(child: Text(_newKeyValue!,
                style: const TextStyle(fontSize: 11.5, fontFamily: 'monospace'),
                overflow: TextOverflow.ellipsis)),
              IconButton(
                icon: const Icon(Icons.copy, size: 14),
                onPressed: () => copyToClipboard(context, _newKeyValue!),
              ),
            ]),
          ),
        Expanded(child: _keys.isEmpty
          ? const XEmptyState('No API keys', icon: Icons.vpn_key_outlined)
          : RefreshIndicator(
              onRefresh: _load,
              child: ListView.builder(
                padding: const EdgeInsets.fromLTRB(12, 4, 12, 80),
                itemCount: _keys.length,
                itemBuilder: (_, i) {
                  final k  = _keys[i] as Map<String,dynamic>;
                  final id = k['id'] as int? ?? 0;
                  return Card(
                    margin: const EdgeInsets.only(bottom: 8),
                    child: ListTile(
                      leading: Container(
                        width: 38, height: 38,
                        decoration: BoxDecoration(
                          color: const Color(0xFF6366F1).withValues(alpha: .1),
                          borderRadius: BorderRadius.circular(9)),
                        child: const Icon(Icons.vpn_key, size: 18, color: Color(0xFF6366F1))),
                      title: Text(str(k['name'] ?? k['label']),
                        style: const TextStyle(fontWeight: FontWeight.w700)),
                      subtitle: Text('Created ${timeAgo(k['created_at'])}  ·  ${str(k['prefix'] ?? str(k['key_prefix'] ?? 'xck_...'))}',
                        style: const TextStyle(fontSize: 11)),
                      trailing: IconButton(
                        icon: const Icon(Icons.delete_outline, color: Colors.redAccent, size: 18),
                        onPressed: () async {
                          if (await xConfirm(context, 'Revoke Key', 'This key will stop working immediately.')) {
                            final ok = await widget.api.deleteApiKey(id);
                            if (context.mounted) xSnack(context, ok ? 'Key revoked' : 'Failed', error: !ok);
                            setState(() => _newKeyValue = null);
                            _load();
                          }
                        },
                      ),
                    ),
                  );
                },
              ),
            )),
      ]),
    );
  }

  void _showCreate() {
    final nameCtrl = TextEditingController();
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('Create API Key'),
            const SizedBox(height: 16),
            xField(nameCtrl, 'Key name / label'),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.add, size: 16),
              label: const Text('Create'),
              onPressed: () async {
                Navigator.pop(context);
                final res = await widget.api.createApiKey({'name': nameCtrl.text});
                if (!mounted) return;
                final key = str(res?['key'] ?? res?['api_key'] ?? '');
                if (key.isNotEmpty) setState(() => _newKeyValue = key);
                xSnack(context, key.isNotEmpty ? 'Key created — copy it now!' : 'Failed', error: key.isEmpty);
                _load();
              },
            )),
          ]),
        ),
      ),
    );
  }
}

// ── Integrations tab ──────────────────────────────────────────────────────────

class _IntegrationsTab extends StatefulWidget {
  final DashboardApi api;
  const _IntegrationsTab({required this.api});
  @override State<_IntegrationsTab> createState() => _IntegrationsTabState();
}

class _IntegrationsTabState extends State<_IntegrationsTab> with AutomaticKeepAliveClientMixin {
  @override bool get wantKeepAlive => true;
  List _integrations = [];
  bool _loading      = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _integrations = await widget.api.integrations();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (_loading) return xLoading();
    if (_integrations.isEmpty) return const XEmptyState('No integrations', icon: Icons.extension_outlined);
    return RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        itemCount: _integrations.length,
        itemBuilder: (_, i) {
          final intg    = _integrations[i] as Map<String,dynamic>;
          final enabled = intg['enabled'] == true;
          final name    = str(intg['name'] ?? intg['integration_type']);
          return Card(
            margin: const EdgeInsets.only(bottom: 8),
            child: ListTile(
              leading: Container(
                width: 38, height: 38,
                decoration: BoxDecoration(
                  color: (enabled ? const Color(0xFF22C55E) : Colors.grey).withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(9)),
                child: Icon(_integIcon(name), size: 20,
                  color: enabled ? const Color(0xFF22C55E) : Colors.grey)),
              title: Text(name, style: const TextStyle(fontWeight: FontWeight.w700)),
              subtitle: Text(str(intg['description'] ?? intg['type'] ?? ''),
                maxLines: 1, overflow: TextOverflow.ellipsis),
              trailing: Row(mainAxisSize: MainAxisSize.min, children: [
                Switch(
                  value: enabled,
                  onChanged: (_) async {
                    final ok = await widget.api.toggleIntegration(name.toLowerCase(), !enabled);
                    if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
                    _load();
                  },
                ),
                IconButton(
                  icon: const Icon(Icons.science_outlined, size: 18),
                  tooltip: 'Test',
                  onPressed: () async {
                    final ok = await widget.api.testIntegration(name.toLowerCase());
                    if (context.mounted) xSnack(context, ok ? 'Test successful' : 'Test failed', error: !ok);
                  },
                ),
              ]),
            ),
          );
        },
      ),
    );
  }

  IconData _integIcon(String name) {
    final n = name.toLowerCase();
    if (n.contains('slack'))       return Icons.chat_bubble;
    if (n.contains('jira'))        return Icons.bug_report;
    if (n.contains('email'))       return Icons.email;
    if (n.contains('pager'))       return Icons.notifications_active;
    if (n.contains('elastic'))     return Icons.search;
    if (n.contains('siem'))        return Icons.security;
    if (n.contains('webhook'))     return Icons.webhook;
    if (n.contains('s3') || n.contains('aws')) return Icons.cloud;
    return Icons.extension;
  }
}

// ── Roles tab ─────────────────────────────────────────────────────────────────

class _RolesTab extends StatefulWidget {
  final DashboardApi api;
  const _RolesTab({required this.api});
  @override State<_RolesTab> createState() => _RolesTabState();
}

class _RolesTabState extends State<_RolesTab> with AutomaticKeepAliveClientMixin {
  @override bool get wantKeepAlive => true;
  List _roles   = [];
  bool _loading = true;

  final _builtIn = ['platform_admin', 'admin', 'analyst', 'viewer', 'readonly'];

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _roles = await widget.api.customRoles();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.add),
        label: const Text('New Role'),
      ),
      body: ListView(
        padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
        children: [
          SectionTitle('Built-in Roles'),
          ..._builtIn.map((r) => Card(
            margin: const EdgeInsets.only(bottom: 6),
            child: ListTile(
              leading: const Icon(Icons.lock, size: 18, color: Colors.grey),
              title: Text(r, style: const TextStyle(fontWeight: FontWeight.w700)),
              trailing: Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: Colors.grey.withValues(alpha: .1),
                  borderRadius: BorderRadius.circular(8)),
                child: const Text('Built-in', style: TextStyle(fontSize: 11, color: Colors.grey)),
              ),
            ),
          )),
          if (_roles.isNotEmpty) ...[
            const SizedBox(height: 16),
            SectionTitle('Custom Roles'),
            ..._roles.map((r) {
              final role = r as Map<String,dynamic>;
              final id   = role['id'] as int? ?? 0;
              return Card(
                margin: const EdgeInsets.only(bottom: 6),
                child: ListTile(
                  leading: const Icon(Icons.admin_panel_settings, size: 18, color: Color(0xFF6366F1)),
                  title: Text(str(role['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                  subtitle: Text(str(role['description'] ?? ''),
                    maxLines: 1, overflow: TextOverflow.ellipsis),
                  trailing: IconButton(
                    icon: const Icon(Icons.delete_outline, color: Colors.redAccent, size: 18),
                    onPressed: () async {
                      if (await xConfirm(context, 'Delete Role', 'Delete custom role "${str(role["name"])}"?')) {
                        final ok = await widget.api.deleteCustomRole(id);
                        if (context.mounted) xSnack(context, ok ? 'Deleted' : 'Failed', error: !ok);
                        _load();
                      }
                    },
                  ),
                ),
              );
            }),
          ],
        ],
      ),
    );
  }

  void _showCreate() {
    final nameCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('New Custom Role'),
            const SizedBox(height: 16),
            xField(nameCtrl, 'Role Name'),
            const SizedBox(height: 10),
            xField(descCtrl, 'Description (optional)'),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton(
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createCustomRole({'name': nameCtrl.text, 'description': descCtrl.text, 'permissions': []});
                if (context.mounted) xSnack(context, ok ? 'Role created' : 'Failed', error: !ok);
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

// ─────────────────────────────────────────────────────────────────────────────
// Tenants Screen
// ─────────────────────────────────────────────────────────────────────────────

class TenantsScreen extends StatefulWidget {
  final DashboardApi api;
  const TenantsScreen({super.key, required this.api});
  @override State<TenantsScreen> createState() => _TenantsState();
}

class _TenantsState extends State<TenantsScreen> {
  List _tenants = [];
  bool _loading = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    _tenants = await widget.api.tenants();
    if (!mounted) return;
    setState(() => _loading = false);
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      floatingActionButton: FloatingActionButton.extended(
        onPressed: _showCreate,
        icon: const Icon(Icons.add_business),
        label: const Text('New Tenant'),
      ),
      body: _tenants.isEmpty
        ? const XEmptyState('No tenants', icon: Icons.business_outlined)
        : RefreshIndicator(
            onRefresh: _load,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(12, 10, 12, 80),
              itemCount: _tenants.length,
              itemBuilder: (_, i) {
                final t       = _tenants[i] as Map<String,dynamic>;
                final id      = t['id'] as int? ?? 0;
                final active  = t['is_active'] != false;
                final plan    = str(t['plan'] ?? t['subscription_plan'] ?? 'free');
                return Card(
                  margin: const EdgeInsets.only(bottom: 8),
                  child: ListTile(
                    leading: Container(
                      width: 40, height: 40,
                      decoration: BoxDecoration(
                        color: (active ? const Color(0xFF3B82F6) : Colors.grey).withValues(alpha: .1),
                        borderRadius: BorderRadius.circular(10)),
                      child: Icon(Icons.business,
                        color: active ? const Color(0xFF3B82F6) : Colors.grey)),
                    title: Text(str(t['name']), style: const TextStyle(fontWeight: FontWeight.w700)),
                    subtitle: Row(children: [
                      StatusChip(active ? 'active' : 'disabled'),
                      const SizedBox(width: 6),
                      Text(plan, style: const TextStyle(fontSize: 11.5, color: Colors.grey)),
                    ]),
                    trailing: Switch(
                      value: active,
                      onChanged: (_) async {
                        final ok = await widget.api.toggleTenant(id);
                        if (context.mounted) xSnack(context, ok ? 'Updated' : 'Failed', error: !ok);
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

  void _showCreate() {
    final nameCtrl = TextEditingController();
    final domainCtrl = TextEditingController();
    showModalBottomSheet(context: context, isScrollControlled: true, builder: (_) =>
      Padding(
        padding: EdgeInsets.only(bottom: MediaQuery.of(context).viewInsets.bottom),
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            sheetHeader('New Tenant'),
            const SizedBox(height: 16),
            xField(nameCtrl,   'Tenant Name'),
            const SizedBox(height: 10),
            xField(domainCtrl, 'Domain (optional)'),
            const SizedBox(height: 16),
            SizedBox(width: double.infinity, child: FilledButton.icon(
              icon: const Icon(Icons.add_business, size: 16),
              label: const Text('Create Tenant'),
              onPressed: () async {
                Navigator.pop(context);
                final ok = await widget.api.createTenant({
                  'name': nameCtrl.text, 'domain': domainCtrl.text, 'plan': 'free',
                });
                if (context.mounted) xSnack(context, ok ? 'Tenant created' : 'Failed', error: !ok);
                _load();
              },
            )),
          ]),
        ),
      ),
    );
  }
}
