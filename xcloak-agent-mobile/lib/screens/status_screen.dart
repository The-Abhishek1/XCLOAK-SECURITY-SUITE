import 'package:flutter/material.dart';
import 'package:flutter_background_service/flutter_background_service.dart';

import '../services/enrollment_service.dart';
import '../services/posture_collector.dart';
import '../services/secure_storage.dart';
import '../services/threat_detector.dart';
import 'setup_screen.dart';

class StatusScreen extends StatefulWidget {
  const StatusScreen({super.key});

  @override
  State<StatusScreen> createState() => _StatusScreenState();
}

class _StatusScreenState extends State<StatusScreen> {
  bool _serviceRunning = false;
  bool _rooted        = false;
  bool _devMode       = false;
  List<String> _sideloaded = [];
  String _osVersion   = '';
  String? _deviceId;

  @override
  void initState() {
    super.initState();
    _refresh();
  }

  Future<void> _refresh() async {
    final posture   = await PostureCollector.collect();
    final sideloaded = await ThreatDetector.sideloadedPackages();
    final deviceId  = await SecureStore.deviceId();
    final running   = await FlutterBackgroundService().isRunning();

    if (!mounted) return;
    setState(() {
      _serviceRunning = running;
      _rooted         = posture.isRooted;
      _devMode        = posture.developerModeOn;
      _osVersion      = posture.osVersion;
      _sideloaded     = sideloaded;
      _deviceId       = deviceId?.toString();
    });
  }

  Future<void> _toggleService() async {
    final service = FlutterBackgroundService();
    if (_serviceRunning) {
      service.invoke('stop');
    } else {
      await service.startService();
    }
    await Future.delayed(const Duration(milliseconds: 500));
    await _refresh();
  }

  Future<void> _unenroll() async {
    final confirmed = await showDialog<bool>(
      context: context,
      builder: (_) => AlertDialog(
        title: const Text('Unenroll Device'),
        content: const Text('This will remove the agent token and stop monitoring. Continue?'),
        actions: [
          TextButton(onPressed: () => Navigator.pop(context, false), child: const Text('Cancel')),
          TextButton(
            onPressed: () => Navigator.pop(context, true),
            child: const Text('Unenroll', style: TextStyle(color: Colors.red)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    await EnrollmentService.unenroll();
    if (!mounted) return;
    Navigator.pushReplacement(
      context,
      MaterialPageRoute(builder: (_) => const SetupScreen()),
    );
  }

  @override
  Widget build(BuildContext context) {
    final risk = _rooted || _sideloaded.isNotEmpty;

    return Scaffold(
      appBar: AppBar(
        title: const Text('XCloak Agent'),
        actions: [
          IconButton(icon: const Icon(Icons.refresh), onPressed: _refresh),
        ],
      ),
      body: RefreshIndicator(
        onRefresh: _refresh,
        child: ListView(
          padding: const EdgeInsets.all(16),
          children: [
            _StatusCard(
              title: 'Agent Status',
              icon: _serviceRunning ? Icons.shield : Icons.shield_outlined,
              color: _serviceRunning ? Colors.green : Colors.grey,
              value: _serviceRunning ? 'Active' : 'Stopped',
              trailing: Switch(
                value: _serviceRunning,
                onChanged: (_) => _toggleService(),
              ),
            ),
            const SizedBox(height: 12),
            _StatusCard(
              title: 'Risk Level',
              icon: risk ? Icons.warning_amber : Icons.check_circle,
              color: risk ? Colors.orange : Colors.green,
              value: risk ? 'Action needed' : 'All clear',
            ),
            const SizedBox(height: 12),
            _InfoCard(title: 'Device Info', children: [
              _Row('OS', _osVersion),
              _Row('Device ID', _deviceId ?? '—'),
            ]),
            const SizedBox(height: 12),
            _InfoCard(title: 'Security Checks', children: [
              _Check('Rooted / Jailbroken', !_rooted),
              _Check('Developer Options off', !_devMode),
              _Check('No sideloaded apps', _sideloaded.isEmpty),
            ]),
            if (_sideloaded.isNotEmpty) ...[
              const SizedBox(height: 12),
              _InfoCard(
                title: 'Sideloaded Apps (${_sideloaded.length})',
                children: _sideloaded
                    .take(10)
                    .map((p) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 2),
                          child: Text(p, style: const TextStyle(fontFamily: 'monospace', fontSize: 12)),
                        ))
                    .toList(),
              ),
            ],
            const SizedBox(height: 24),
            OutlinedButton.icon(
              onPressed: _unenroll,
              icon: const Icon(Icons.logout, color: Colors.red),
              label: const Text('Unenroll Device', style: TextStyle(color: Colors.red)),
            ),
          ],
        ),
      ),
    );
  }
}

class _StatusCard extends StatelessWidget {
  final String title;
  final IconData icon;
  final Color color;
  final String value;
  final Widget? trailing;

  const _StatusCard({
    required this.title,
    required this.icon,
    required this.color,
    required this.value,
    this.trailing,
  });

  @override
  Widget build(BuildContext context) {
    return Card(
      child: ListTile(
        leading: Icon(icon, color: color, size: 32),
        title: Text(title, style: const TextStyle(fontWeight: FontWeight.bold)),
        subtitle: Text(value, style: TextStyle(color: color)),
        trailing: trailing,
      ),
    );
  }
}

class _InfoCard extends StatelessWidget {
  final String title;
  final List<Widget> children;
  const _InfoCard({required this.title, required this.children});

  @override
  Widget build(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(title, style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 14)),
            const Divider(),
            ...children,
          ],
        ),
      ),
    );
  }
}

Widget _Row(String label, String value) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Expanded(flex: 2, child: Text(label, style: const TextStyle(color: Colors.grey))),
          Expanded(flex: 3, child: Text(value)),
        ],
      ),
    );

Widget _Check(String label, bool passing) => Padding(
      padding: const EdgeInsets.symmetric(vertical: 4),
      child: Row(
        children: [
          Icon(passing ? Icons.check_circle : Icons.cancel,
              color: passing ? Colors.green : Colors.red, size: 18),
          const SizedBox(width: 8),
          Text(label),
        ],
      ),
    );
