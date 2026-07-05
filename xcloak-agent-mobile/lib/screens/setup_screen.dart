import 'package:flutter/material.dart';

import '../services/enrollment_service.dart';
import 'status_screen.dart';

class SetupScreen extends StatefulWidget {
  const SetupScreen({super.key});

  @override
  State<SetupScreen> createState() => _SetupScreenState();
}

class _SetupScreenState extends State<SetupScreen> {
  final _formKey    = GlobalKey<FormState>();
  final _serverCtrl = TextEditingController();
  final _tokenCtrl  = TextEditingController();
  final _emailCtrl  = TextEditingController();
  final _apiKeyCtrl = TextEditingController();

  bool _loading  = false;
  bool _advanced = false;
  String? _error;

  @override
  void dispose() {
    _serverCtrl.dispose();
    _tokenCtrl.dispose();
    _emailCtrl.dispose();
    _apiKeyCtrl.dispose();
    super.dispose();
  }

  Future<void> _enroll() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() { _loading = true; _error = null; });

    try {
      await EnrollmentService.enroll(
        serverUrl:   _serverCtrl.text.trim(),
        enrollToken: _tokenCtrl.text.trim(),
        ownerEmail:  _emailCtrl.text.trim(),
        apiKey:      _apiKeyCtrl.text.trim(),
      );
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => const StatusScreen()),
      );
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('XCloak Agent Setup')),
      body: SafeArea(
        child: SingleChildScrollView(
          padding: const EdgeInsets.all(24),
          child: Form(
            key: _formKey,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.stretch,
              children: [
                const Icon(Icons.security, size: 64, color: Colors.blue),
                const SizedBox(height: 16),
                const Text(
                  'Enroll this device with your XCloak server.',
                  textAlign: TextAlign.center,
                  style: TextStyle(fontSize: 16),
                ),
                const SizedBox(height: 28),

                // ── Required fields ────────────────────────────────────────
                TextFormField(
                  controller: _serverCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Server URL *',
                    hintText: 'https://xcloak.example.com',
                    prefixIcon: Icon(Icons.dns),
                    border: OutlineInputBorder(),
                  ),
                  keyboardType: TextInputType.url,
                  autocorrect: false,
                  validator: (v) {
                    if (v == null || v.trim().isEmpty) return 'Required';
                    final uri = Uri.tryParse(v.trim());
                    if (uri == null || !uri.hasAuthority) return 'Enter a valid URL';
                    return null;
                  },
                ),
                const SizedBox(height: 14),

                TextFormField(
                  controller: _tokenCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Enrollment Token *',
                    hintText: 'xck-enroll-…',
                    prefixIcon: Icon(Icons.vpn_key),
                    border: OutlineInputBorder(),
                  ),
                  autocorrect: false,
                  validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
                ),
                const SizedBox(height: 14),

                TextFormField(
                  controller: _emailCtrl,
                  decoration: const InputDecoration(
                    labelText: 'Your email (optional)',
                    hintText: 'you@company.com',
                    prefixIcon: Icon(Icons.email),
                    border: OutlineInputBorder(),
                  ),
                  keyboardType: TextInputType.emailAddress,
                ),

                // ── Advanced / API key ─────────────────────────────────────
                const SizedBox(height: 8),
                GestureDetector(
                  onTap: () => setState(() => _advanced = !_advanced),
                  child: Row(
                    children: [
                      Icon(_advanced ? Icons.expand_less : Icons.expand_more,
                          size: 18, color: Colors.blue),
                      const SizedBox(width: 4),
                      const Text('Advanced (dashboard access)',
                          style: TextStyle(color: Colors.blue, fontSize: 13)),
                    ],
                  ),
                ),

                if (_advanced) ...[
                  const SizedBox(height: 12),
                  TextFormField(
                    controller: _apiKeyCtrl,
                    decoration: const InputDecoration(
                      labelText: 'Admin API Key (optional)',
                      hintText: 'xck_…',
                      helperText: 'Create one under Settings → API Keys in the dashboard.',
                      prefixIcon: Icon(Icons.admin_panel_settings),
                      border: OutlineInputBorder(),
                    ),
                    autocorrect: false,
                    obscureText: true,
                  ),
                ],

                // ── Error ──────────────────────────────────────────────────
                if (_error != null) ...[
                  const SizedBox(height: 14),
                  Text(
                    _error!,
                    style: TextStyle(color: Theme.of(context).colorScheme.error),
                    textAlign: TextAlign.center,
                  ),
                ],

                const SizedBox(height: 24),
                FilledButton.icon(
                  onPressed: _loading ? null : _enroll,
                  icon: _loading
                      ? const SizedBox(
                          width: 18, height: 18,
                          child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                        )
                      : const Icon(Icons.check),
                  label: Text(_loading ? 'Enrolling…' : 'Enroll Device'),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
