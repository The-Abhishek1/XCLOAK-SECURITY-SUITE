import 'dart:async';
import 'dart:math';

import 'package:flutter_background_service/flutter_background_service.dart';

import 'command_service.dart';
import 'enrollment_service.dart';
import 'log_forwarder.dart';
import 'posture_collector.dart';
import 'secure_storage.dart';
import 'threat_detector.dart';
import 'api_client.dart';

// Background foreground service entry point.
// Timers drive all periodic agent tasks. Jitter is applied to each interval
// to avoid thundering-herd issues on the backend when many devices start up
// simultaneously (e.g. after an OS update reboot).

const _checkinInterval   = Duration(minutes: 5);
const _cmdPollInterval   = Duration(minutes: 2);
const _logInterval       = Duration(minutes: 10);
const _inventoryInterval = Duration(minutes: 30);
const _threatInterval    = Duration(minutes: 15);

// Maximum jitter added to the first tick of each collector.
const _maxJitterSeconds = 30;

int _consecutiveCheckinFailures = 0;
const _maxConsecutiveFailures = 5; // after this many failures → degrade notification

Future<void> initializeBackgroundService() async {
  final service = FlutterBackgroundService();
  await service.configure(
    androidConfiguration: AndroidConfiguration(
      onStart: onServiceStart,
      autoStart: false,
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
Future<bool> onIosBackground(ServiceInstance service) async => true;

@pragma('vm:entry-point')
void onServiceStart(ServiceInstance service) async {
  if (service is AndroidServiceInstance) {
    service.setAsForegroundService();
  }

  service.on('stop').listen((_) => service.stopSelf());

  // Immediate first runs (no jitter on startup to confirm liveness quickly).
  await _checkIn(service);
  await _pollCommands();

  // Staggered periodic timers.
  _schedulePeriodic(_checkinInterval,   () => _checkIn(service));
  _schedulePeriodic(_cmdPollInterval,   _pollCommands);
  _schedulePeriodic(_logInterval,       LogForwarder.forwardBatch);
  _schedulePeriodic(_inventoryInterval, _runInventory);
  _schedulePeriodic(_threatInterval,    _runThreatScan);
}

// Applies random jitter before the first tick, then uses a fixed interval.
void _schedulePeriodic(Duration interval, Future<void> Function() fn) {
  final jitterMs = Random().nextInt(_maxJitterSeconds * 1000);
  Timer(Duration(milliseconds: jitterMs), () {
    fn();
    Timer.periodic(interval, (_) => fn());
  });
}

// ── Check-in ─────────────────────────────────────────────────────────────────

Future<void> _checkIn(ServiceInstance service) async {
  final enrolled = await SecureStore.isEnrolled();
  if (!enrolled) return;

  try {
    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    final agentId  = await SecureStore.agentId();
    if (deviceId == null || agentId == null) return;

    final posture = await PostureCollector.collect();

    // MDM device posture update
    await client.put('/api/mdm/devices/$deviceId/checkin', posture.toJson());

    // Enriched agent heartbeat
    await client.post('/api/agents/heartbeat', {
      'agent_id':       agentId,
      'version':        '1.0.0',
      'platform':       'android',
      'battery_level':  posture.batteryLevel,
      'battery_charging': posture.batteryCharging,
      'network_type':   posture.networkType,
      'is_rooted':      posture.isRooted,
      'developer_mode': posture.developerModeOn,
      'storage_free_gb': posture.storageFreeGb,
      'storage_total_gb': posture.storageTotalGb,
      'vpn_active':     posture.vpnActive,
      'os_version':     posture.osVersion,
      'security_patch': posture.securityPatchLevel,
    });

    _consecutiveCheckinFailures = 0;
    _updateNotification(service, 'Monitoring device security…');

  } on ApiException catch (e) {
    if (e.statusCode == 403 || e.statusCode == 401) {
      // Server unenrolled this device — wipe credentials.
      await EnrollmentService.unenroll();
      _updateNotification(service, 'Unenrolled — open app to re-enroll');
    } else {
      _onCheckinFailure(service, 'Check-in error: ${e.statusCode}');
    }
  } catch (e) {
    _onCheckinFailure(service, 'Check-in failed');
  }
}

void _onCheckinFailure(ServiceInstance service, String reason) {
  _consecutiveCheckinFailures++;
  if (_consecutiveCheckinFailures >= _maxConsecutiveFailures) {
    _updateNotification(service, 'Agent degraded — server unreachable');
  }
}

void _updateNotification(ServiceInstance service, String content) {
  if (service is AndroidServiceInstance) {
    service.setForegroundNotificationInfo(
      title: 'XCloak Agent',
      content: content,
    );
  }
}

// ── Command poll ──────────────────────────────────────────────────────────────

Future<void> _pollCommands() async {
  final enrolled = await SecureStore.isEnrolled();
  if (!enrolled) return;
  await CommandService.pollAndExecute();
}

// ── Inventory scan (app list) ─────────────────────────────────────────────────

Future<void> _runInventory() async {
  final enrolled = await SecureStore.isEnrolled();
  if (!enrolled) return;
  await ThreatDetector.runInventoryScan();
}

// ── Threat scan (posture re-check + threat summary ship) ─────────────────────

Future<void> _runThreatScan() async {
  final enrolled = await SecureStore.isEnrolled();
  if (!enrolled) return;

  try {
    final client   = await ApiClient.fromStorage();
    final deviceId = await SecureStore.deviceId();
    if (deviceId == null) return;

    final summary = await ThreatDetector.threatSummary();
    await client.post('/api/mdm/devices/$deviceId/threat-scan', summary);
  } catch (_) {}
}
