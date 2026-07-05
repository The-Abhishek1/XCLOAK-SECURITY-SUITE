import 'package:flutter/material.dart';

import '../api.dart';
import '../widgets.dart';

// ── AI Assistant ──────────────────────────────────────────────────────────────

class AIAssistantScreen extends StatefulWidget {
  final DashboardApi api;
  const AIAssistantScreen({super.key, required this.api});
  @override State<AIAssistantScreen> createState() => _AIAssistantState();
}

class _AIAssistantState extends State<AIAssistantScreen> {
  final _ctrl    = TextEditingController();
  final _scroll  = ScrollController();
  List _messages = [];
  bool _sending  = false;
  String? _sid;

  @override void initState() { super.initState(); _loadHistory(); }
  @override void dispose()   { _ctrl.dispose(); _scroll.dispose(); super.dispose(); }

  Future<void> _loadHistory() async {
    final h = await widget.api.chatHistory();
    if (!mounted) return;
    setState(() {
      _messages = h.map((m) {
        final map = m as Map<String,dynamic>;
        return {'role': map['role'] ?? 'user', 'content': str(map['content'] ?? map['message'])};
      }).toList();
    });
    _scrollDown();
  }

  Future<void> _send() async {
    final text = _ctrl.text.trim();
    if (text.isEmpty || _sending) return;
    _ctrl.clear();
    setState(() {
      _messages.add({'role': 'user', 'content': text});
      _sending = true;
    });
    _scrollDown();
    final r = await widget.api.aiChat(text, sessionId: _sid);
    if (!mounted) return;
    final reply = r != null ? str(r['response'] ?? r['content'] ?? r['message'] ?? '') : 'Error: no response';
    if (r?['session_id'] != null) _sid = str(r!['session_id']);
    setState(() { _messages.add({'role': 'assistant', 'content': reply}); _sending = false; });
    _scrollDown();
  }

  void _scrollDown() {
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (_scroll.hasClients) _scroll.animateTo(_scroll.position.maxScrollExtent, duration: const Duration(milliseconds: 300), curve: Curves.easeOut);
    });
  }

  Future<void> _clear() async {
    if (!await xConfirm(context, 'Clear Chat', 'Clear chat history?')) return;
    await widget.api.clearChatHistory();
    setState(() { _messages.clear(); _sid = null; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      Padding(
        padding: const EdgeInsets.fromLTRB(12, 4, 4, 0),
        child: Row(children: [
          const Icon(Icons.smart_toy, color: Colors.blue, size: 18),
          const SizedBox(width: 6),
          const Expanded(child: Text('XCloak AI Assistant', style: TextStyle(fontWeight: FontWeight.bold))),
          TextButton(onPressed: _clear, child: const Text('Clear', style: TextStyle(fontSize: 12))),
        ]),
      ),
      const Divider(height: 1),
      Expanded(child: _messages.isEmpty
        ? const Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.smart_toy, size: 48, color: Colors.blue),
            SizedBox(height: 12),
            Text('Ask anything about your security posture', style: TextStyle(color: Colors.grey)),
          ]))
        : ListView.builder(
            controller: _scroll,
            padding: const EdgeInsets.all(12),
            itemCount: _messages.length,
            itemBuilder: (_, i) {
              final m       = _messages[i] as Map<String,dynamic>;
              final isUser  = m['role'] == 'user';
              return Align(
                alignment: isUser ? Alignment.centerRight : Alignment.centerLeft,
                child: Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  constraints: BoxConstraints(maxWidth: MediaQuery.of(context).size.width * 0.82),
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  decoration: BoxDecoration(
                    color: isUser ? Theme.of(context).colorScheme.primary : Theme.of(context).colorScheme.surfaceVariant,
                    borderRadius: BorderRadius.only(
                      topLeft: const Radius.circular(16),
                      topRight: const Radius.circular(16),
                      bottomLeft: Radius.circular(isUser ? 16 : 4),
                      bottomRight: Radius.circular(isUser ? 4 : 16),
                    ),
                  ),
                  child: SelectableText(
                    str(m['content']),
                    style: TextStyle(
                      color: isUser ? Colors.white : null,
                      fontSize: 14,
                    ),
                  ),
                ),
              );
            },
          ),
      ),
      if (_sending) const Padding(
        padding: EdgeInsets.only(left: 16, bottom: 4),
        child: Row(children: [
          SizedBox(width: 14, height: 14, child: CircularProgressIndicator(strokeWidth: 2)),
          SizedBox(width: 8),
          Text('Thinking…', style: TextStyle(fontSize: 12, color: Colors.grey)),
        ]),
      ),
      const Divider(height: 1),
      Padding(
        padding: EdgeInsets.only(left: 12, right: 8, top: 8, bottom: MediaQuery.of(context).viewInsets.bottom + 8),
        child: Row(children: [
          Expanded(child: TextField(
            controller: _ctrl,
            decoration: const InputDecoration(hintText: 'Ask a question…', border: OutlineInputBorder(), isDense: true, contentPadding: EdgeInsets.symmetric(horizontal: 12, vertical: 10)),
            textInputAction: TextInputAction.send,
            onSubmitted: (_) => _send(),
            maxLines: 3,
            minLines: 1,
          )),
          const SizedBox(width: 8),
          IconButton.filled(onPressed: _sending ? null : _send, icon: const Icon(Icons.send)),
        ]),
      ),
    ]);
  }
}

// ── Settings ──────────────────────────────────────────────────────────────────

class SettingsScreen extends StatefulWidget {
  final DashboardApi api;
  const SettingsScreen({super.key, required this.api});
  @override State<SettingsScreen> createState() => _SettingsState();
}

class _SettingsState extends State<SettingsScreen> with SingleTickerProviderStateMixin {
  late final TabController _tabs;
  List _users = [], _keys = [], _integrations = [], _roles = [];
  bool _loading = true;

  @override void initState() { super.initState(); _tabs = TabController(length: 4, vsync: this); _load(); }
  @override void dispose() { _tabs.dispose(); super.dispose(); }

  Future<void> _load() async {
    setState(() => _loading = true);
    final res = await Future.wait([widget.api.users(), widget.api.apiKeys(), widget.api.integrations(), widget.api.customRoles()]);
    if (!mounted) return;
    setState(() { _users = res[0]; _keys = res[1]; _integrations = res[2]; _roles = res[3]; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    return Column(children: [
      TabBar(controller: _tabs, isScrollable: true, tabs: const [
        Tab(text: 'Users'), Tab(text: 'API Keys'), Tab(text: 'Integrations'), Tab(text: 'Roles'),
      ]),
      if (_loading) const Expanded(child: Center(child: CircularProgressIndicator()))
      else Expanded(child: TabBarView(controller: _tabs, children: [
        _usersTab(), _keysTab(), _integrationsTab(), _rolesTab(),
      ])),
    ]);
  }

  // ── Users tab ───────────────────────────────────────

  Widget _usersTab() => Scaffold(
    body: _users.isEmpty ? const XEmptyState('No users') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _users.length,
        itemBuilder: (_, i) {
          final u  = _users[i] as Map<String,dynamic>;
          final id = u['id'] as int? ?? 0;
          return Card(child: ListTile(
            leading: CircleAvatar(backgroundColor: Colors.indigo, child: Text(str(u['username'] ?? u['email'] ?? '?').substring(0,1).toUpperCase(), style: const TextStyle(color: Colors.white))),
            title: Text(str(u['username'] ?? u['email'])),
            subtitle: Text('${str(u['role'])}  ·  ${u['mfa_enabled'] == true ? "MFA on" : "no MFA"}'),
            trailing: PopupMenuButton<String>(
              onSelected: (v) async {
                if (v == 'reset')  { await widget.api.resetUserPassword(id); xSnack(context, 'Reset email sent'); }
                if (v == 'delete') {
                  if (context.mounted && await xConfirm(context, 'Delete User', 'Delete ${str(u['username'])}?')) { await widget.api.deleteUser(id); _load(); }
                }
              },
              itemBuilder: (_) => const [
                PopupMenuItem(value: 'reset',  child: Text('Reset Password')),
                PopupMenuItem(value: 'delete', child: Text('Delete', style: TextStyle(color: Colors.red))),
              ],
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(
      heroTag: 'usr_add',
      onPressed: _createUser,
      child: const Icon(Icons.person_add),
    ),
  );

  void _createUser() {
    final emailCtrl = TextEditingController();
    final passCtrl  = TextEditingController();
    String role = 'analyst';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New User', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(emailCtrl, 'Email', keyboardType: TextInputType.emailAddress),
          const SizedBox(height: 10),
          xField(passCtrl, 'Password', obscure: true),
          const SizedBox(height: 10),
          xDropdown('Role', role, ['admin','analyst','viewer','responder'], (v) => ss(() => role = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createUser({'email': emailCtrl.text.trim(), 'password': passCtrl.text, 'role': role});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  // ── API Keys tab ────────────────────────────────────

  Widget _keysTab() => Scaffold(
    body: _keys.isEmpty ? const XEmptyState('No API keys') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _keys.length,
        itemBuilder: (_, i) {
          final k  = _keys[i] as Map<String,dynamic>;
          final id = k['id'] as int? ?? 0;
          return Card(child: ListTile(
            leading: const Icon(Icons.vpn_key),
            title: Text(str(k['name'] ?? 'Key $id')),
            subtitle: Text('${str(k['key_prefix'] ?? k['prefix'] ?? '••••')}****  ·  ${timeAgo(k['created_at'])}'),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline, color: Colors.red),
              onPressed: () async {
                if (await xConfirm(context, 'Revoke Key', 'Revoke API key "${str(k['name'])}"?')) { await widget.api.deleteApiKey(id); _load(); }
              },
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(heroTag: 'key_add', onPressed: _createKey, child: const Icon(Icons.add)),
  );

  void _createKey() {
    final nameCtrl = TextEditingController();
    String role = 'agent';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New API Key', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Key Name'),
          const SizedBox(height: 10),
          xDropdown('Role', role, ['agent','admin','read_only'], (v) => ss(() => role = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              final r = await widget.api.createApiKey({'name': nameCtrl.text.trim(), 'role': role});
              if (!mounted) return;
              _load();
              if (r != null) {
                showDetailSheet(context, 'API Key Created', [
                  ('Name', str(r['name'])),
                  ('Key', str(r['key'] ?? r['api_key'] ?? '(see server)')),
                ]);
              }
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }

  // ── Integrations tab ────────────────────────────────

  Widget _integrationsTab() => _integrations.isEmpty ? const XEmptyState('No integrations configured') : RefreshIndicator(
    onRefresh: _load,
    child: ListView.builder(
      padding: const EdgeInsets.all(8),
      itemCount: _integrations.length,
      itemBuilder: (_, i) {
        final it      = _integrations[i] as Map<String,dynamic>;
        final id      = it['id'] as int? ?? 0;
        final enabled = it['enabled'] as bool? ?? it['is_enabled'] as bool? ?? false;
        return Card(child: ListTile(
          leading: Icon(Icons.extension, color: enabled ? Colors.green : Colors.grey),
          title: Text(str(it['name'] ?? it['type'])),
          subtitle: Text('${str(it['type'] ?? '')}  ·  ${enabled ? "Active" : "Disabled"}'),
          trailing: Switch(
            value: enabled,
            onChanged: (v) async { await widget.api.toggleIntegration(id, v); _load(); },
          ),
        ));
      },
    ),
  );

  // ── Custom Roles tab ─────────────────────────────────

  Widget _rolesTab() => Scaffold(
    body: _roles.isEmpty ? const XEmptyState('No custom roles') : RefreshIndicator(
      onRefresh: _load,
      child: ListView.builder(
        padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
        itemCount: _roles.length,
        itemBuilder: (_, i) {
          final r  = _roles[i] as Map<String,dynamic>;
          final id = r['id'] as int? ?? 0;
          return Card(child: ListTile(
            leading: const Icon(Icons.manage_accounts),
            title: Text(str(r['name'])),
            subtitle: Text('${(r['permissions'] as List?)?.length ?? 0} permissions  ·  ${r['user_count'] ?? 0} users'),
            trailing: IconButton(
              icon: const Icon(Icons.delete_outline, color: Colors.red),
              onPressed: () async {
                if (await xConfirm(context, 'Delete Role', 'Delete this role?')) { await widget.api.deleteCustomRole(id); _load(); }
              },
            ),
          ));
        },
      ),
    ),
    floatingActionButton: FloatingActionButton(heroTag: 'role_add', onPressed: _createRole, child: const Icon(Icons.add)),
  );

  void _createRole() {
    final nameCtrl = TextEditingController();
    final descCtrl = TextEditingController();
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Custom Role', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Role Name'),
          const SizedBox(height: 10),
          xField(descCtrl, 'Description'),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createCustomRole({'name': nameCtrl.text.trim(), 'description': descCtrl.text.trim(), 'permissions': []});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      ),
    );
  }
}

// ── Tenants ───────────────────────────────────────────────────────────────────

class TenantsScreen extends StatefulWidget {
  final DashboardApi api;
  const TenantsScreen({super.key, required this.api});
  @override State<TenantsScreen> createState() => _TenantsState();
}

class _TenantsState extends State<TenantsScreen> {
  List _tenants = [];
  bool _loading  = true;

  @override void initState() { super.initState(); _load(); }
  Future<void> _load() async {
    setState(() => _loading = true);
    final r = await widget.api.tenants();
    if (!mounted) return;
    setState(() { _tenants = r; _loading = false; });
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return xLoading();
    return Scaffold(
      body: _tenants.isEmpty ? const XEmptyState('No tenants') : RefreshIndicator(
        onRefresh: _load,
        child: ListView.builder(
          padding: const EdgeInsets.fromLTRB(8, 8, 8, 80),
          itemCount: _tenants.length,
          itemBuilder: (_, i) {
            final t  = _tenants[i] as Map<String,dynamic>;
            final id = t['id'] as int? ?? 0;
            return Card(child: ListTile(
              leading: CircleAvatar(
                backgroundColor: Colors.deepPurple,
                child: Text(str(t['name'], 'T').substring(0,1).toUpperCase(), style: const TextStyle(color: Colors.white)),
              ),
              title: Text(str(t['name'] ?? 'Tenant $id'), style: const TextStyle(fontWeight: FontWeight.w600)),
              subtitle: Text('${str(t['plan'] ?? '')}  ·  ${t['user_count'] ?? 0} users  ·  ${t['agent_count'] ?? 0} agents'),
              trailing: StatusChip(str(t['status'] ?? 'active')),
              onTap: () => showDetailSheet(context, str(t['name']), [
                ('ID',        '$id'),
                ('Plan',      str(t['plan'] ?? '')),
                ('Status',    str(t['status'] ?? '')),
                ('Users',     '${t['user_count'] ?? 0}'),
                ('Agents',    '${t['agent_count'] ?? 0}'),
                ('Created',   timeAgo(t['created_at'])),
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
    String plan = 'basic';
    showModalBottomSheet(
      context: context, isScrollControlled: true,
      builder: (ctx) => StatefulBuilder(builder: (ctx, ss) => Padding(
        padding: EdgeInsets.only(left: 16, right: 16, top: 16, bottom: MediaQuery.of(ctx).viewInsets.bottom + 16),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          const Text('New Tenant', style: TextStyle(fontSize: 16, fontWeight: FontWeight.bold)),
          const SizedBox(height: 12),
          xField(nameCtrl, 'Tenant Name'),
          const SizedBox(height: 10),
          xDropdown('Plan', plan, ['basic','professional','enterprise'], (v) => ss(() => plan = v!)),
          const SizedBox(height: 12),
          SizedBox(width: double.infinity, child: FilledButton(
            onPressed: () async {
              Navigator.pop(ctx);
              await widget.api.createTenant({'name': nameCtrl.text.trim(), 'plan': plan});
              _load();
            },
            child: const Text('Create'),
          )),
        ]),
      )),
    );
  }
}
