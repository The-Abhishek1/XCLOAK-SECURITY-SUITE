import 'dart:async';
import 'dart:io';
import 'package:flutter/material.dart';
import '../admin/api.dart';
import '../admin/shell.dart';
import '../services/api_client.dart';
import '../services/secure_storage.dart';

class AdminLoginScreen extends StatefulWidget {
  const AdminLoginScreen({super.key});
  @override State<AdminLoginScreen> createState() => _AdminLoginScreenState();
}

class _AdminLoginScreenState extends State<AdminLoginScreen>
    with SingleTickerProviderStateMixin {
  late final TabController _tabs = TabController(length: 2, vsync: this);

  // Password tab
  final _emailCtrl    = TextEditingController();
  final _passCtrl     = TextEditingController();
  final _serverCtrl   = TextEditingController();
  final _pwForm       = GlobalKey<FormState>();

  // API key tab
  final _keyCtrl      = TextEditingController();
  final _keyServerCtrl = TextEditingController();
  final _keyForm      = GlobalKey<FormState>();

  bool    _loading    = false;
  bool    _obscure    = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _prefillServerUrl();
  }

  Future<void> _prefillServerUrl() async {
    final url = await SecureStore.serverUrl() ?? '';
    if (mounted) {
      _serverCtrl.text    = url;
      _keyServerCtrl.text = url;
    }
  }

  @override
  void dispose() {
    _tabs.dispose();
    _emailCtrl.dispose();
    _passCtrl.dispose();
    _serverCtrl.dispose();
    _keyCtrl.dispose();
    _keyServerCtrl.dispose();
    super.dispose();
  }

  String _normalizeUrl(String raw) {
    var url = raw.trim();
    if (url.isEmpty) return url;
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
      url = 'https://$url';
    }
    return url.endsWith('/') ? url.substring(0, url.length - 1) : url;
  }

  Future<void> _signInWithPassword() async {
    if (!(_pwForm.currentState?.validate() ?? false)) return;
    setState(() { _loading = true; _error = null; });

    final serverUrl = _normalizeUrl(_serverCtrl.text);
    try {
      final api = await DashboardApi.login(
        serverUrl,
        _emailCtrl.text.trim(),
        _passCtrl.text,
      );
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => AdminApp(api: api)),
      );
    } on AdminUnauthorizedException catch (e) {
      setState(() { _error = e.message; _loading = false; });
    } on ApiException catch (e) {
      setState(() { _error = 'Server error: ${e.message}'; _loading = false; });
    } on SocketException catch (e) {
      setState(() { _error = 'Cannot reach server at $serverUrl\n${e.message}'; _loading = false; });
    } on TimeoutException {
      setState(() { _error = 'Request timed out. Server may be unreachable.'; _loading = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  Future<void> _signInWithApiKey() async {
    if (!(_keyForm.currentState?.validate() ?? false)) return;
    setState(() { _loading = true; _error = null; });

    final serverUrl = _normalizeUrl(_keyServerCtrl.text);
    try {
      final api = await DashboardApi.loginWithApiKey(
        serverUrl,
        _keyCtrl.text.trim(),
      );
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => AdminApp(api: api)),
      );
    } on AdminUnauthorizedException catch (e) {
      setState(() { _error = e.message; _loading = false; });
    } on ApiException catch (e) {
      setState(() { _error = 'Server error: ${e.message}'; _loading = false; });
    } on SocketException catch (e) {
      setState(() { _error = 'Cannot reach server at $serverUrl\n${e.message}'; _loading = false; });
    } on TimeoutException {
      setState(() { _error = 'Request timed out. Server may be unreachable.'; _loading = false; });
    } catch (e) {
      setState(() { _error = e.toString(); _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs   = Theme.of(context).colorScheme;
    final dark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: dark ? const Color(0xFF0A0F1E) : const Color(0xFFF0F4FF),
      body: CustomScrollView(
        slivers: [

          // ── Hero header ──────────────────────────────────────────────────
          SliverToBoxAdapter(
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [Color(0xFF1A237E), Color(0xFF283593), Color(0xFF1565C0)],
                ),
              ),
              child: SafeArea(
                bottom: false,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(24, 32, 24, 28),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Row(children: [
                      Container(
                        width: 44, height: 44,
                        decoration: BoxDecoration(
                          color: Colors.white.withOpacity(.15),
                          borderRadius: BorderRadius.circular(12),
                        ),
                        child: const Icon(Icons.admin_panel_settings, color: Colors.white, size: 24),
                      ),
                      const SizedBox(width: 12),
                      Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        const Text('Admin Console',
                            style: TextStyle(color: Colors.white, fontSize: 18,
                                fontWeight: FontWeight.w700)),
                        Text('XCloak Security Platform',
                            style: TextStyle(color: Colors.white.withOpacity(.65), fontSize: 12)),
                      ]),
                    ]),
                    const SizedBox(height: 20),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                      decoration: BoxDecoration(
                        color: Colors.amber.withOpacity(.15),
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: Colors.amber.withOpacity(.4)),
                      ),
                      child: Row(children: [
                        Icon(Icons.lock_outline, color: Colors.amber.shade300, size: 14),
                        const SizedBox(width: 8),
                        Expanded(
                          child: Text(
                            'Restricted access. Only authorized platform administrators may log in. '
                            'All attempts are logged and audited.',
                            style: TextStyle(color: Colors.amber.shade200, fontSize: 11),
                          ),
                        ),
                      ]),
                    ),
                  ]),
                ),
              ),
            ),
          ),

          // ── Login form ───────────────────────────────────────────────────
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 24, 20, 40),
              child: Column(children: [

                // Tab bar
                Container(
                  decoration: BoxDecoration(
                    color: dark ? const Color(0xFF1E293B) : const Color(0xFFE2E8F0),
                    borderRadius: BorderRadius.circular(12),
                  ),
                  child: TabBar(
                    controller: _tabs,
                    onTap: (_) => setState(() => _error = null),
                    indicator: BoxDecoration(
                      color: cs.primary,
                      borderRadius: BorderRadius.circular(10),
                    ),
                    indicatorSize: TabBarIndicatorSize.tab,
                    labelColor: Colors.white,
                    unselectedLabelColor: cs.onSurface.withOpacity(.55),
                    labelStyle: const TextStyle(fontWeight: FontWeight.w600, fontSize: 13),
                    dividerColor: Colors.transparent,
                    tabs: const [
                      Tab(icon: Icon(Icons.password, size: 16), text: 'Email & Password'),
                      Tab(icon: Icon(Icons.vpn_key, size: 16), text: 'API Key'),
                    ],
                  ),
                ),

                const SizedBox(height: 20),

                // Error banner
                if (_error != null) ...[
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: const Color(0xFFEF4444).withOpacity(.08),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0xFFEF4444).withOpacity(.3)),
                    ),
                    child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      const Icon(Icons.error_outline, color: Color(0xFFEF4444), size: 16),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(_error!,
                            style: const TextStyle(fontSize: 12, color: Color(0xFFEF4444))),
                      ),
                      GestureDetector(
                        onTap: () => setState(() => _error = null),
                        child: const Icon(Icons.close, size: 14, color: Color(0xFFEF4444)),
                      ),
                    ]),
                  ),
                  const SizedBox(height: 16),
                ],

                SizedBox(
                  height: 360,
                  child: TabBarView(
                    controller: _tabs,
                    children: [
                      // ── Tab 1: Email + Password ──────────────────────────
                      Form(
                        key: _pwForm,
                        child: Column(children: [
                          TextFormField(
                            controller: _serverCtrl,
                            decoration: InputDecoration(
                              labelText: 'Server URL',
                              hintText: 'https://xcloak.example.com',
                              prefixIcon: Icon(Icons.dns_outlined, color: cs.primary),
                              helperText: 'Pre-filled from enrollment — edit if different',
                            ),
                            keyboardType: TextInputType.url,
                            autocorrect: false,
                            validator: (v) {
                              if (v == null || v.trim().isEmpty) return 'Required';
                              return null;
                            },
                          ),
                          const SizedBox(height: 14),
                          TextFormField(
                            controller: _emailCtrl,
                            decoration: InputDecoration(
                              labelText: 'Email or Username',
                              hintText: 'admin@xcloak.local',
                              prefixIcon: Icon(Icons.person_outline, color: cs.primary),
                            ),
                            keyboardType: TextInputType.emailAddress,
                            autocorrect: false,
                            validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
                          ),
                          const SizedBox(height: 14),
                          TextFormField(
                            controller: _passCtrl,
                            obscureText: _obscure,
                            decoration: InputDecoration(
                              labelText: 'Password',
                              prefixIcon: Icon(Icons.lock_outline, color: cs.primary),
                              suffixIcon: IconButton(
                                icon: Icon(_obscure ? Icons.visibility_off : Icons.visibility,
                                    size: 18),
                                onPressed: () => setState(() => _obscure = !_obscure),
                              ),
                            ),
                            validator: (v) => (v == null || v.isEmpty) ? 'Required' : null,
                          ),
                          const SizedBox(height: 24),
                          FilledButton.icon(
                            onPressed: _loading ? null : _signInWithPassword,
                            icon: _loading
                                ? const SizedBox(width: 16, height: 16,
                                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                                : const Icon(Icons.login, size: 18),
                            label: Text(_loading ? 'Signing in…' : 'Sign In as Admin'),
                            style: FilledButton.styleFrom(
                              backgroundColor: const Color(0xFF1565C0),
                              minimumSize: const Size(double.infinity, 48),
                            ),
                          ),
                        ]),
                      ),

                      // ── Tab 2: API Key ───────────────────────────────────
                      Form(
                        key: _keyForm,
                        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          TextFormField(
                            controller: _keyServerCtrl,
                            decoration: InputDecoration(
                              labelText: 'Server URL',
                              hintText: 'https://xcloak.example.com',
                              prefixIcon: Icon(Icons.dns_outlined, color: cs.primary),
                            ),
                            keyboardType: TextInputType.url,
                            autocorrect: false,
                            validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
                          ),
                          const SizedBox(height: 14),
                          TextFormField(
                            controller: _keyCtrl,
                            decoration: InputDecoration(
                              labelText: 'API Key',
                              hintText: 'xck_…',
                              prefixIcon: Icon(Icons.vpn_key_outlined, color: cs.primary),
                              helperText: 'Generate from Settings → API Keys in the web dashboard',
                            ),
                            autocorrect: false,
                            obscureText: true,
                            validator: (v) {
                              if (v == null || v.trim().isEmpty) return 'Required';
                              if (!v.trim().startsWith('xck_')) return 'API key must start with xck_';
                              return null;
                            },
                          ),
                          const SizedBox(height: 8),
                          Container(
                            padding: const EdgeInsets.all(10),
                            decoration: BoxDecoration(
                              color: cs.primary.withOpacity(.06),
                              borderRadius: BorderRadius.circular(8),
                              border: Border.all(color: cs.primary.withOpacity(.2)),
                            ),
                            child: Row(children: [
                              Icon(Icons.info_outline, size: 14, color: cs.primary),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  'The API key must have admin or platform_admin role. '
                                  'Create one in the web dashboard under Settings → API Keys.',
                                  style: TextStyle(fontSize: 11, color: cs.onSurface.withOpacity(.6)),
                                ),
                              ),
                            ]),
                          ),
                          const SizedBox(height: 24),
                          FilledButton.icon(
                            onPressed: _loading ? null : _signInWithApiKey,
                            icon: _loading
                                ? const SizedBox(width: 16, height: 16,
                                    child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white))
                                : const Icon(Icons.key, size: 18),
                            label: Text(_loading ? 'Verifying…' : 'Connect with API Key'),
                            style: FilledButton.styleFrom(
                              backgroundColor: const Color(0xFF1565C0),
                              minimumSize: const Size(double.infinity, 48),
                            ),
                          ),
                        ]),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 8),
                TextButton.icon(
                  onPressed: () => Navigator.of(context).pop(),
                  icon: const Icon(Icons.arrow_back, size: 16),
                  label: const Text('Back to Mode Selection'),
                  style: TextButton.styleFrom(foregroundColor: cs.onSurface.withOpacity(.5)),
                ),
              ]),
            ),
          ),
        ],
      ),
    );
  }
}
