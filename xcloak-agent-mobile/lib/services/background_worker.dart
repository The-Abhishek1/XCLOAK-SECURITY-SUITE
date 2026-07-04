import 'dart:async';

import 'package:flutter_background_service/flutter_background_service.dart';
import 'package:flutter_background_service/flutter_background_service_android.dart';

import 'command_service.dart';
import 'log_forwarder.dart';
import 'posture_collector.dart';
import 'secure_storage.dart';
import 'threat_detector.dart';
import 'api_client.dart';

// Background foreground service entry point.
// The service runs continuously with a persistent notification. Timers inside
// the isolate drive the agent's periodic tasks.

const _checkinInterval  = Duration(minutes: 5);
const _cmdPollInterval  = Duration(minutes: 2);
const _logInterval      = Duration(minutes: 10);
const _inventoryInterval = Duration(minutes: 30);

Future<void> initializeBackgroundService() async {
  final service = FlutterBackgroundService();

  await service.configure(
    androidConfiguration: AndroidConfiguration(
      onStart: onServiceStart,
      isForegroundMode: true,
      notificationChannelId: 'xcloak_agent',
      initialNotificationTitle: 'XCloak Agent',
      initialNotificationContent: 'Monitoring device security…',
      foregroundServiceNotificationId: 888,
    ),
    iosConfiguration: IosConfiguration(
      autoStart: true,
      onForeground: onServiceStart,
      onBackground: onIosBackground,
    ),
  );
}

@pragma('vm:entry-point')
Future<bool> onIosBackground(ServiceInstance service) async {
  return true;
}

@pragma('vm:entry-point')
void onServiceStart(ServiceInstance service) async {
  if (service is AndroidServiceInstance) {
    service.setAsForegroundService();
  }

  service.on('stop').listen((_) => service.stopSelf());

  // Run immediately on start, then on schedule.
  await _checkIn();
  await _pollCommands();

  Timer.periodic(_checkinInterval, (_) => _checkIn());
  Timer.periodic(_cmdPollInterval, (_) => _pollCommands());
  Timer.periodic(_logInterval, (_) => LogForwarder.forwardBatch());

  // Stagger inventory scan to avoid startup spike.
  Timer(const Duration(minutes: 1), () {
    ThreatDetector.runInventoryScan();
    Timer.periodic(_inventoryInterval, (_) => ThreatDetector.runInventoryScan());
  });
}

Future<void> _checkIn() async {
  final enrolled = await SecureStore.isEnrolled();
  if (!enrolled) return;

  try {
    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    final agentId  = await SecureStore.agentId();
    if (deviceId == null || agentId == null) return;

    final posture = await PostureCollector.collect();

    // Posture update
    await client.put('/api/mdm/devices/$deviceId/checkin', posture.toJson());

    // Agent heartbeat (keeps the agent record alive in the dashboard)
    await client.post('/api/agents/heartbeat', {
      'agent_id': agentId,
      'version':  '1.0.0',
    });
  } catch (_) {}
}

Future<void> _pollCommands() async {
  final enrolled = await SecureStore.isEnrolled();
  if (!enrolled) return;
  await CommandService.pollAndExecute();
}
