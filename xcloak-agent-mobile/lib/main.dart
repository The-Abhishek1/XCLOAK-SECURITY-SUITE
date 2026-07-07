import 'package:flutter/material.dart';
import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:permission_handler/permission_handler.dart';

import 'screens/mode_select.dart';
import 'screens/setup_screen.dart';
import 'services/background_worker.dart';
import 'services/secure_storage.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeBackgroundService();
  final status = await Permission.notification.request();
  if (status.isGranted) {
    FlutterBackgroundService().startService();
  }
  runApp(const XCloakAgentApp());
}

ThemeData _buildTheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final cs = ColorScheme.fromSeed(
    seedColor: const Color(0xFF1565C0),
    brightness: brightness,
  );
  return ThemeData(
    colorScheme: cs,
    useMaterial3: true,
    cardTheme: CardTheme(
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(12),
        side: BorderSide(color: dark ? const Color(0xFF1E293B) : const Color(0xFFE2E8F0)),
      ),
      margin: EdgeInsets.zero,
    ),
    appBarTheme: const AppBarTheme(
      centerTitle: false,
      elevation: 0,
      scrolledUnderElevation: 1,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: dark ? const Color(0xFF1E293B) : const Color(0xFFF8FAFC),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: dark ? const Color(0xFF334155) : const Color(0xFFE2E8F0)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: BorderSide(color: dark ? const Color(0xFF334155) : const Color(0xFFE2E8F0)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(10),
        borderSide: const BorderSide(color: Color(0xFF1565C0), width: 2),
      ),
      contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
    ),
    filledButtonTheme: FilledButtonThemeData(
      style: FilledButton.styleFrom(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(10)),
        padding: const EdgeInsets.symmetric(vertical: 16),
        textStyle: const TextStyle(fontSize: 15, fontWeight: FontWeight.w600, letterSpacing: .2),
      ),
    ),
    chipTheme: ChipThemeData(
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
      side: BorderSide(color: dark ? const Color(0xFF334155) : const Color(0xFFE2E8F0)),
      padding: const EdgeInsets.symmetric(horizontal: 4),
      labelStyle: const TextStyle(fontSize: 12),
    ),
    dividerTheme: DividerThemeData(
      space: 1, thickness: 1,
      color: dark ? const Color(0xFF1E293B) : const Color(0xFFE2E8F0),
    ),
    listTileTheme: const ListTileThemeData(horizontalTitleGap: 12),
  );
}

class XCloakAgentApp extends StatelessWidget {
  const XCloakAgentApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'XCloak',
      debugShowCheckedModeBanner: false,
      theme: _buildTheme(Brightness.light),
      darkTheme: _buildTheme(Brightness.dark),
      home: const _EntryPoint(),
    );
  }
}

// Routes to:
//  · SetupScreen      — not enrolled yet
//  · ModeSelectScreen — enrolled; user picks Agent Mode or Admin Console
class _EntryPoint extends StatefulWidget {
  const _EntryPoint();
  @override State<_EntryPoint> createState() => _EntryPointState();
}

class _EntryPointState extends State<_EntryPoint> {
  bool _resolved = false;
  bool _enrolled = false;

  @override
  void initState() {
    super.initState();
    _resolve();
  }

  Future<void> _resolve() async {
    final enrolled = await SecureStore.isEnrolled();
    if (!mounted) return;
    setState(() { _enrolled = enrolled; _resolved = true; });
  }

  @override
  Widget build(BuildContext context) {
    if (!_resolved) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return _enrolled ? const ModeSelectScreen() : const SetupScreen();
  }
}
