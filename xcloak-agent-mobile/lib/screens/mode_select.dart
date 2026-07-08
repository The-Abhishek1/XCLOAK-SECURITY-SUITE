import 'package:flutter/material.dart';
import '../admin/api.dart';
import '../admin/shell.dart';
import '../services/api_client.dart';
import '../services/enrollment_service.dart';
import '../services/secure_storage.dart';
import 'admin_login.dart';
import 'agent_shell.dart';
import 'setup_screen.dart';

/// Entry point shown when the device is enrolled.
/// The user chooses between Agent Mode (this device's monitoring) and
/// Admin Console (full platform management — requires separate login).
class ModeSelectScreen extends StatefulWidget {
  const ModeSelectScreen({super.key});
  @override State<ModeSelectScreen> createState() => _ModeSelectState();
}

class _ModeSelectState extends State<ModeSelectScreen> {
  bool _checkingAdminSession = true;
  bool _hasAdminSession      = false;
  bool _verifyingAgent       = false;
  String _adminEmail         = '';
  String _adminRole          = '';

  @override
  void initState() {
    super.initState();
    _checkAdminSession();
  }

  Future<void> _checkAdminSession() async {
    final cookie = await SecureStore.adminCookie();
    final email  = await SecureStore.adminEmail() ?? '';
    final role   = await SecureStore.adminRole()  ?? '';
    // Only mark "has session" if there is a stored credential — actual
    // validity is verified lazily when the user taps "Resume session".
    final hasSession = (cookie != null && cookie.isNotEmpty) || true == await _hasApiKeySession();
    if (mounted) {
      setState(() {
        _checkingAdminSession = false;
        _hasAdminSession      = hasSession && email.isNotEmpty;
        _adminEmail           = email;
        _adminRole            = role;
      });
    }
  }

  Future<bool> _hasApiKeySession() async {
    final key = await SecureStore.apiKey();
    return key != null && key.startsWith('xck_');
  }

  Future<void> _goAgentMode() async {
    setState(() => _verifyingAgent = true);
    try {
      final client = await ApiClient.fromStorage();
      await client.get('/api/agents/self/summary');
      // Server confirmed the device is still enrolled — proceed.
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => const AgentShell()),
      );
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.statusCode == 403 || e.statusCode == 401) {
        // Server rejected the request — device was unenrolled remotely.
        await EnrollmentService.unenroll();
        if (!mounted) return;
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('This device has been unenrolled. Please re-enroll to continue.'),
            backgroundColor: Colors.red,
          ),
        );
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (_) => const SetupScreen()),
        );
      } else {
        // Some other server error (500, etc.) — still let them in so
        // temporary connectivity issues don't block the agent UI.
        if (!mounted) return;
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (_) => const AgentShell()),
        );
      }
    } catch (_) {
      // Network unreachable — allow access so offline scenarios still work.
      if (!mounted) return;
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => const AgentShell()),
      );
    } finally {
      if (mounted) setState(() => _verifyingAgent = false);
    }
  }

  Future<void> _goAdminMode() async {
    // Try to resume an existing session first.
    final existing = await DashboardApi.createFromSession();
    if (!mounted) return;
    if (existing != null) {
      Navigator.pushReplacement(
        context,
        MaterialPageRoute(builder: (_) => AdminApp(api: existing)),
      );
    } else {
      // Clear stale session info and show login.
      await SecureStore.clearAdminSession();
      if (!mounted) return;
      Navigator.push(
        context,
        MaterialPageRoute(builder: (_) => const AdminLoginScreen()),
      ).then((_) => _checkAdminSession());
    }
  }

  Future<void> _signOutAdmin() async {
    await SecureStore.clearAdminSession();
    setState(() { _hasAdminSession = false; _adminEmail = ''; _adminRole = ''; });
  }

  @override
  Widget build(BuildContext context) {
    final dark = Theme.of(context).brightness == Brightness.dark;
    final cs   = Theme.of(context).colorScheme;

    return Scaffold(
      backgroundColor: dark ? const Color(0xFF070C18) : const Color(0xFFF0F4FF),
      body: CustomScrollView(
        slivers: [

          // ── Top bar ─────────────────────────────────────────────────────
          SliverAppBar(
            expandedHeight: 180,
            pinned: true,
            backgroundColor: const Color(0xFF0D1B3E),
            flexibleSpace: FlexibleSpaceBar(
              background: Container(
                decoration: const BoxDecoration(
                  gradient: LinearGradient(
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                    colors: [Color(0xFF0D1B3E), Color(0xFF1565C0), Color(0xFF0288D1)],
                  ),
                ),
                child: SafeArea(
                  child: Padding(
                    padding: const EdgeInsets.fromLTRB(24, 20, 24, 16),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        Row(children: [
                          Container(
                            width: 48, height: 48,
                            decoration: BoxDecoration(
                              color: Colors.white.withValues(alpha: .15),
                              borderRadius: BorderRadius.circular(14),
                            ),
                            child: const Icon(Icons.security, color: Colors.white, size: 26),
                          ),
                          const SizedBox(width: 12),
                          Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            const Text('XCloak',
                                style: TextStyle(color: Colors.white,
                                    fontSize: 22, fontWeight: FontWeight.w800, letterSpacing: -.3)),
                            Text('Security Suite',
                                style: TextStyle(color: Colors.white.withValues(alpha: .65), fontSize: 12)),
                          ]),
                        ]),
                        const SizedBox(height: 12),
                        Text('Select your mode',
                            style: TextStyle(color: Colors.white.withValues(alpha: .7), fontSize: 13)),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),

          // ── Mode cards ──────────────────────────────────────────────────
          SliverPadding(
            padding: const EdgeInsets.fromLTRB(20, 24, 20, 0),
            sliver: SliverList(
              delegate: SliverChildListDelegate([

                // Agent Mode card
                _ModeCard(
                  icon: Icons.shield_outlined,
                  iconColor: const Color(0xFF3B82F6),
                  gradientColors: const [Color(0xFF1E3A5F), Color(0xFF1A2D50)],
                  lightGradient: const [Color(0xFFEFF6FF), Color(0xFFDBEAFE)],
                  title: 'Agent Mode',
                  subtitle: 'Endpoint protection for this device',
                  features: const [
                    'Real-time threat monitoring',
                    'Device posture & compliance',
                    'Threat alerts & activity log',
                    'No admin credentials required',
                  ],
                  badgeText: _verifyingAgent ? 'VERIFYING…' : 'ENROLLED',
                  badgeColor: _verifyingAgent ? Colors.orange : const Color(0xFF22C55E),
                  onTap: _verifyingAgent ? null : _goAgentMode,
                  dark: dark,
                ),

                const SizedBox(height: 16),

                // Admin Console card
                _ModeCard(
                  icon: Icons.admin_panel_settings_outlined,
                  iconColor: const Color(0xFFA855F7),
                  gradientColors: const [Color(0xFF2D1B69), Color(0xFF1E1245)],
                  lightGradient: const [Color(0xFFF5F3FF), Color(0xFFEDE9FE)],
                  title: 'Admin Console',
                  subtitle: 'Full platform management',
                  features: const [
                    'All 53 management sections',
                    'Agents, alerts & cases',
                    'Firewall rules & policies',
                    'Requires admin credentials',
                  ],
                  badgeText: _hasAdminSession ? 'SESSION ACTIVE' : 'REQUIRES LOGIN',
                  badgeColor: _hasAdminSession ? const Color(0xFF22C55E) : const Color(0xFFF59E0B),
                  onTap: _checkingAdminSession ? null : _goAdminMode,
                  dark: dark,
                  sessionInfo: _hasAdminSession ? _SessionInfo(
                    email: _adminEmail,
                    role: _adminRole,
                    onSignOut: _signOutAdmin,
                  ) : null,
                ),

                const SizedBox(height: 32),

                // Footer note
                Center(
                  child: Text(
                    'Agent mode only shows data for this enrolled device.\n'
                    'Admin console provides access to all platform data.',
                    textAlign: TextAlign.center,
                    style: TextStyle(fontSize: 11, color: cs.onSurface.withValues(alpha: .4),
                        height: 1.5),
                  ),
                ),
                const SizedBox(height: 40),
              ]),
            ),
          ),
        ],
      ),
    );
  }
}

// ─────────────────────────────────────────────────────────────────────────────

class _SessionInfo {
  final String email;
  final String role;
  final VoidCallback onSignOut;
  const _SessionInfo({required this.email, required this.role, required this.onSignOut});
}

class _ModeCard extends StatelessWidget {
  final IconData icon;
  final Color iconColor;
  final List<Color> gradientColors;
  final List<Color> lightGradient;
  final String title;
  final String subtitle;
  final List<String> features;
  final String badgeText;
  final Color badgeColor;
  final VoidCallback? onTap;
  final bool dark;
  final _SessionInfo? sessionInfo;

  const _ModeCard({
    required this.icon,
    required this.iconColor,
    required this.gradientColors,
    required this.lightGradient,
    required this.title,
    required this.subtitle,
    required this.features,
    required this.badgeText,
    required this.badgeColor,
    required this.onTap,
    required this.dark,
    this.sessionInfo,
  });

  @override
  Widget build(BuildContext context) {
    final colors = dark ? gradientColors : lightGradient;
    final textColor = dark ? Colors.white : const Color(0xFF1E293B);
    final subColor  = dark ? Colors.white60 : const Color(0xFF64748B);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(20),
        child: Ink(
          decoration: BoxDecoration(
            gradient: LinearGradient(
              begin: Alignment.topLeft,
              end: Alignment.bottomRight,
              colors: colors,
            ),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(
              color: dark ? iconColor.withValues(alpha: .25) : iconColor.withValues(alpha: .35),
              width: 1.5,
            ),
            boxShadow: [
              BoxShadow(
                color: iconColor.withValues(alpha: .12),
                blurRadius: 20,
                offset: const Offset(0, 6),
              ),
            ],
          ),
          child: Padding(
            padding: const EdgeInsets.all(20),
            child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [

              // Header row
              Row(children: [
                Container(
                  width: 48, height: 48,
                  decoration: BoxDecoration(
                    color: iconColor.withValues(alpha: .15),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: iconColor.withValues(alpha: .3)),
                  ),
                  child: Icon(icon, color: iconColor, size: 26),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                    Text(title, style: TextStyle(color: textColor,
                        fontSize: 17, fontWeight: FontWeight.w700)),
                    const SizedBox(height: 2),
                    Text(subtitle, style: TextStyle(color: subColor, fontSize: 12)),
                  ]),
                ),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                  decoration: BoxDecoration(
                    color: badgeColor.withValues(alpha: .15),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: badgeColor.withValues(alpha: .4)),
                  ),
                  child: Text(badgeText,
                      style: TextStyle(color: badgeColor, fontSize: 9,
                          fontWeight: FontWeight.w700, letterSpacing: .5)),
                ),
              ]),

              const SizedBox(height: 16),
              Divider(color: iconColor.withValues(alpha: .15), height: 1),
              const SizedBox(height: 14),

              // Features
              ...features.map((f) => Padding(
                padding: const EdgeInsets.only(bottom: 8),
                child: Row(children: [
                  Icon(Icons.check_circle_outline, size: 14, color: iconColor),
                  const SizedBox(width: 8),
                  Text(f, style: TextStyle(color: subColor, fontSize: 12)),
                ]),
              )),

              // Session info
              if (sessionInfo != null) ...[
                const SizedBox(height: 8),
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                  decoration: BoxDecoration(
                    color: Colors.white.withValues(alpha: .06),
                    borderRadius: BorderRadius.circular(10),
                  ),
                  child: Row(children: [
                    const Icon(Icons.account_circle_outlined, size: 14, color: Color(0xFF22C55E)),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Text(sessionInfo!.email,
                            style: const TextStyle(color: Color(0xFF22C55E),
                                fontSize: 11, fontWeight: FontWeight.w600)),
                        Text(sessionInfo!.role,
                            style: TextStyle(color: subColor, fontSize: 10)),
                      ]),
                    ),
                    GestureDetector(
                      onTap: sessionInfo!.onSignOut,
                      child: Text('Sign out',
                          style: TextStyle(color: subColor, fontSize: 10,
                              decoration: TextDecoration.underline)),
                    ),
                  ]),
                ),
              ],

              const SizedBox(height: 16),

              // CTA button
              SizedBox(
                width: double.infinity,
                child: FilledButton.icon(
                  onPressed: onTap,
                  icon: Icon(onTap == null ? Icons.hourglass_empty : Icons.arrow_forward, size: 16),
                  label: Text(
                    title == 'Agent Mode'
                        ? 'Enter Agent Mode'
                        : sessionInfo != null
                            ? 'Resume Admin Session'
                            : 'Login to Admin Console',
                    style: const TextStyle(fontWeight: FontWeight.w600),
                  ),
                  style: FilledButton.styleFrom(
                    backgroundColor: iconColor,
                    foregroundColor: Colors.white,
                    padding: const EdgeInsets.symmetric(vertical: 12),
                    shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
                  ),
                ),
              ),
            ]),
          ),
        ),
      ),
    );
  }
}
