import 'package:flutter/material.dart';
import '../admin/api.dart';
import '../admin/shell.dart';
import '../services/secure_storage.dart';

class AdminLoginScreen extends StatefulWidget {
  const AdminLoginScreen({super.key});
  @override State<AdminLoginScreen> createState() => _AdminLoginScreenState();
}

class _AdminLoginScreenState extends State<AdminLoginScreen> {
  final _email    = TextEditingController();
  final _password = TextEditingController();
  final _form     = GlobalKey<FormState>();

  bool _loading   = false;
  bool _obscure   = true;
  String? _error;

  @override
  void dispose() {
    _email.dispose();
    _password.dispose();
    super.dispose();
  }

  Future<void> _signIn() async {
    if (!(_form.currentState?.validate() ?? false)) return;
    setState(() { _loading = true; _error = null; });

    try {
      final serverUrl = await SecureStore.serverUrl() ?? '';
      if (serverUrl.isEmpty) {
        setState(() { _error = 'Server URL not configured. Re-enroll the device first.'; _loading = false; });
        return;
      }

      final api = await DashboardApi.login(serverUrl, _email.text.trim(), _password.text);

      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => AdminApp(api: api)),
      );
    } on AdminUnauthorizedException catch (e) {
      setState(() { _error = e.message; _loading = false; });
    } on ApiException catch (e) {
      setState(() { _error = 'Server error: ${e.message}'; _loading = false; });
    } catch (e) {
      setState(() { _error = 'Connection failed. Check server URL and network.'; _loading = false; });
    }
  }

  @override
  Widget build(BuildContext context) {
    final cs   = Theme.of(context).colorScheme;
    final dark = Theme.of(context).brightness == Brightness.dark;

    return Scaffold(
      backgroundColor: dark ? const Color(0xFF0A0F1E) : const Color(0xFFF0F4FF),
      body: SafeArea(
        child: Center(
          child: SingleChildScrollView(
            padding: const EdgeInsets.all(28),
            child: ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 400),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  // Logo
                  Container(
                    width: 72,
                    height: 72,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: cs.primary.withOpacity(.12),
                      border: Border.all(color: cs.primary.withOpacity(.3), width: 1.5),
                    ),
                    child: Icon(Icons.admin_panel_settings, color: cs.primary, size: 36),
                  ),
                  const SizedBox(height: 20),
                  Text('Admin Console',
                    style: TextStyle(
                      fontSize: 24, fontWeight: FontWeight.w800,
                      color: dark ? Colors.white : const Color(0xFF0F172A),
                    )),
                  const SizedBox(height: 6),
                  Text('XCloak Security Suite',
                    style: TextStyle(
                      fontSize: 13,
                      color: dark ? Colors.white54 : Colors.grey.shade600,
                      letterSpacing: .5,
                    )),
                  const SizedBox(height: 36),

                  // Form card
                  Container(
                    decoration: BoxDecoration(
                      borderRadius: BorderRadius.circular(16),
                      color: dark ? const Color(0xFF0F172A) : Colors.white,
                      border: Border.all(
                        color: dark ? const Color(0xFF1E293B) : const Color(0xFFE2E8F0),
                      ),
                      boxShadow: [
                        BoxShadow(
                          color: Colors.black.withOpacity(dark ? .3 : .06),
                          blurRadius: 20, offset: const Offset(0, 4),
                        ),
                      ],
                    ),
                    padding: const EdgeInsets.all(24),
                    child: Form(
                      key: _form,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.stretch,
                        children: [
                          // Error banner
                          if (_error != null) ...[
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
                              decoration: BoxDecoration(
                                color: const Color(0xFFEF4444).withOpacity(.1),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(color: const Color(0xFFEF4444).withOpacity(.3)),
                              ),
                              child: Row(children: [
                                const Icon(Icons.error_outline, color: Color(0xFFEF4444), size: 16),
                                const SizedBox(width: 8),
                                Expanded(child: Text(_error!,
                                  style: const TextStyle(color: Color(0xFFEF4444), fontSize: 13))),
                              ]),
                            ),
                            const SizedBox(height: 16),
                          ],

                          // Email
                          TextFormField(
                            controller: _email,
                            keyboardType: TextInputType.emailAddress,
                            textInputAction: TextInputAction.next,
                            decoration: const InputDecoration(
                              labelText: 'Email',
                              prefixIcon: Icon(Icons.email_outlined, size: 18),
                            ),
                            validator: (v) {
                              if (v == null || v.trim().isEmpty) return 'Email required';
                              if (!v.contains('@')) return 'Enter a valid email';
                              return null;
                            },
                          ),
                          const SizedBox(height: 14),

                          // Password
                          TextFormField(
                            controller: _password,
                            obscureText: _obscure,
                            textInputAction: TextInputAction.done,
                            onFieldSubmitted: (_) => _signIn(),
                            decoration: InputDecoration(
                              labelText: 'Password',
                              prefixIcon: const Icon(Icons.lock_outline, size: 18),
                              suffixIcon: IconButton(
                                icon: Icon(_obscure ? Icons.visibility_outlined : Icons.visibility_off_outlined, size: 18),
                                onPressed: () => setState(() => _obscure = !_obscure),
                              ),
                            ),
                            validator: (v) {
                              if (v == null || v.isEmpty) return 'Password required';
                              if (v.length < 4) return 'Password too short';
                              return null;
                            },
                          ),
                          const SizedBox(height: 22),

                          // Sign In button
                          FilledButton(
                            onPressed: _loading ? null : _signIn,
                            style: FilledButton.styleFrom(
                              backgroundColor: cs.primary,
                              disabledBackgroundColor: cs.primary.withOpacity(.5),
                              minimumSize: const Size.fromHeight(50),
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                            ),
                            child: _loading
                              ? const SizedBox(height: 20, width: 20, child: CircularProgressIndicator(color: Colors.white, strokeWidth: 2.5))
                              : const Row(
                                  mainAxisAlignment: MainAxisAlignment.center,
                                  children: [
                                    Icon(Icons.lock_open, size: 18),
                                    SizedBox(width: 8),
                                    Text('Sign In to Admin Console', style: TextStyle(fontSize: 15, fontWeight: FontWeight.w600)),
                                  ],
                                ),
                          ),
                        ],
                      ),
                    ),
                  ),

                  const SizedBox(height: 20),
                  // Disclaimer
                  Text(
                    'Only authorized administrators can access the admin console.\nAll access attempts are logged and audited.',
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 11.5,
                      color: dark ? Colors.white38 : Colors.grey.shade500,
                      height: 1.5,
                    ),
                  ),
                  const SizedBox(height: 20),

                  // Back
                  TextButton.icon(
                    onPressed: () => Navigator.pop(context),
                    icon: const Icon(Icons.arrow_back, size: 16),
                    label: const Text('Back to Agent Mode'),
                    style: TextButton.styleFrom(foregroundColor: cs.primary),
                  ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }
}
