import 'package:flutter/material.dart';
import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:permission_handler/permission_handler.dart';

import 'screens/admin_app.dart';
import 'screens/setup_screen.dart';
import 'screens/status_screen.dart';
import 'services/background_worker.dart';
import 'services/dashboard_api.dart';
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

class XCloakAgentApp extends StatelessWidget {
  const XCloakAgentApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'XCloak',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: const Color(0xFF1565C0)),
        useMaterial3: true,
      ),
      darkTheme: ThemeData(
        colorScheme: ColorScheme.fromSeed(
          seedColor: const Color(0xFF1565C0),
          brightness: Brightness.dark,
        ),
        useMaterial3: true,
      ),
      home: const _EntryPoint(),
    );
  }
}

// Routes to:
//  · SetupScreen   — not enrolled
//  · AdminApp      — enrolled + API key stored (admin mode)
//  · StatusScreen  — enrolled, no API key (agent-only mode)
class _EntryPoint extends StatefulWidget {
  const _EntryPoint();
  @override State<_EntryPoint> createState() => _EntryPointState();
}

class _EntryPointState extends State<_EntryPoint> {
  bool? _enrolled;
  DashboardApi? _adminApi;
  bool _resolved = false;

  @override
  void initState() {
    super.initState();
    _resolve();
  }

  Future<void> _resolve() async {
    final enrolled = await SecureStore.isEnrolled();
    DashboardApi? adminApi;
    if (enrolled) {
      adminApi = await DashboardApi.create();
    }
    if (!mounted) return;
    setState(() {
      _enrolled  = enrolled;
      _adminApi  = adminApi;
      _resolved  = true;
    });
  }

  @override
  Widget build(BuildContext context) {
    if (!_resolved) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    if (!(_enrolled ?? false)) return const SetupScreen();
    if (_adminApi != null) return AdminApp(api: _adminApi!);
    return const StatusScreen();
  }
}
