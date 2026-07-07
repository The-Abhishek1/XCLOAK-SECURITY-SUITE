import 'package:flutter/material.dart';

import '../services/enrollment_service.dart';
import 'mode_select.dart';

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

  bool _loading = false;
  String? _error;

  @override
  void dispose() {
    _serverCtrl.dispose();
    _tokenCtrl.dispose();
    _emailCtrl.dispose();
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
      );
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => const ModeSelectScreen()),
      );
    } catch (e) {
      setState(() => _error = e.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs = Theme.of(context).colorScheme;

    return Scaffold(
      body: CustomScrollView(
        slivers: [

          // ── Hero header ──────────────────────────────────────────────────
          SliverToBoxAdapter(
            child: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topLeft,
                  end: Alignment.bottomRight,
                  colors: [
                    const Color(0xFF0D47A1),
                    const Color(0xFF1565C0),
                    const Color(0xFF0288D1),
                  ],
                ),
              ),
              child: SafeArea(
                bottom: false,
                child: Padding(
                  padding: const EdgeInsets.fromLTRB(28, 40, 28, 36),
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Container(
                      width: 56, height: 56,
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(.18),
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: const Icon(Icons.security, color: Colors.white, size: 30),
                    ),
                    const SizedBox(height: 20),
                    const Text('XCloak',
                        style: TextStyle(
                          color: Colors.white,
                          fontSize: 28, fontWeight: FontWeight.w800, letterSpacing: -.3,
                        )),
                    const SizedBox(height: 4),
                    Text('Endpoint Security Agent',
                        style: TextStyle(color: Colors.white.withOpacity(.75), fontSize: 14)),
                  ]),
                ),
              ),
            ),
          ),

          // ── Form ─────────────────────────────────────────────────────────
          SliverToBoxAdapter(
            child: Padding(
              padding: const EdgeInsets.fromLTRB(20, 28, 20, 40),
              child: Form(
                key: _formKey,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    Text('Enroll this device',
                        style: TextStyle(
                          fontSize: 18, fontWeight: FontWeight.w700,
                          color: cs.onSurface,
                        )),
                    const SizedBox(height: 4),
                    Text('Connect to your XCloak server to start monitoring.',
                        style: TextStyle(fontSize: 13, color: cs.onSurface.withOpacity(.55))),
                    const SizedBox(height: 24),

                    // Server URL
                    TextFormField(
                      controller: _serverCtrl,
                      decoration: InputDecoration(
                        labelText: 'Server URL',
                        hintText: 'https://xcloak.example.com',
                        prefixIcon: Icon(Icons.dns_outlined, color: cs.primary),
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

                    // Enrollment token
                    TextFormField(
                      controller: _tokenCtrl,
                      decoration: InputDecoration(
                        labelText: 'Enrollment Token',
                        hintText: 'xck-enroll-…',
                        prefixIcon: Icon(Icons.vpn_key_outlined, color: cs.primary),
                      ),
                      autocorrect: false,
                      validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
                    ),
                    const SizedBox(height: 14),

                    // Email (optional)
                    TextFormField(
                      controller: _emailCtrl,
                      decoration: InputDecoration(
                        labelText: 'Email (optional)',
                        hintText: 'you@company.com',
                        prefixIcon: Icon(Icons.email_outlined, color: cs.primary),
                      ),
                      keyboardType: TextInputType.emailAddress,
                    ),

                    // Error
                    if (_error != null) ...[
                      const SizedBox(height: 16),
                      Container(
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(
                          color: const Color(0xFFEF4444).withOpacity(.08),
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: const Color(0xFFEF4444).withOpacity(.3)),
                        ),
                        child: Row(children: [
                          const Icon(Icons.error_outline, color: Color(0xFFEF4444), size: 16),
                          const SizedBox(width: 8),
                          Expanded(child: Text(_error!,
                              style: const TextStyle(fontSize: 12, color: Color(0xFFEF4444)))),
                        ]),
                      ),
                    ],

                    const SizedBox(height: 28),
                    FilledButton.icon(
                      onPressed: _loading ? null : _enroll,
                      icon: _loading
                          ? const SizedBox(
                              width: 18, height: 18,
                              child: CircularProgressIndicator(strokeWidth: 2, color: Colors.white),
                            )
                          : const Icon(Icons.check_rounded),
                      label: Text(_loading ? 'Enrolling…' : 'Enroll Device'),
                    ),
                    const SizedBox(height: 12),
                    Text(
                      'Your data stays on your server. XCloak never sends telemetry externally.',
                      textAlign: TextAlign.center,
                      style: TextStyle(fontSize: 11, color: cs.onSurface.withOpacity(.35)),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
