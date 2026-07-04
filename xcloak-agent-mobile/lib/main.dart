import 'package:flutter/material.dart';

import 'screens/setup_screen.dart';
import 'screens/status_screen.dart';
import 'services/background_worker.dart';
import 'services/secure_storage.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await initializeBackgroundService();
  runApp(const XCloakAgentApp());
}

class XCloakAgentApp extends StatelessWidget {
  const XCloakAgentApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'XCloak Agent',
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

// Decides whether to show setup or the status screen based on enrollment state.
class _EntryPoint extends StatefulWidget {
  const _EntryPoint();

  @override
  State<_EntryPoint> createState() => _EntryPointState();
}

class _EntryPointState extends State<_EntryPoint> {
  bool? _enrolled;

  @override
  void initState() {
    super.initState();
    SecureStore.isEnrolled().then((v) => setState(() => _enrolled = v));
  }

  @override
  Widget build(BuildContext context) {
    if (_enrolled == null) {
      return const Scaffold(body: Center(child: CircularProgressIndicator()));
    }
    return _enrolled! ? const StatusScreen() : const SetupScreen();
  }
}
