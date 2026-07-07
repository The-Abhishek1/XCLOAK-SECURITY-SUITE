import 'package:device_info_plus/device_info_plus.dart';

import 'api_client.dart';
import 'posture_collector.dart';
import 'secure_storage.dart';

class EnrollmentService {
  // Enrolls this device against the XCloak backend. The enriched metadata
  // (manufacturer, SDK, security patch, storage, RAM) lets the server
  // immediately populate the device record without waiting for the first
  // check-in cycle.
  static Future<void> enroll({
    required String serverUrl,
    required String enrollToken,
    String? ownerEmail,
    String? fcmToken,
    String? apiKey,
  }) async {
    final baseUrl = serverUrl.replaceAll(RegExp(r'/+$'), '');
    final client  = ApiClient(baseUrl: baseUrl);

    final udid       = await PostureCollector.deviceUDID();
    final name       = await PostureCollector.deviceName();
    final model      = await PostureCollector.model();
    final posture    = await PostureCollector.collect();
    final androidInfo = await DeviceInfoPlugin().androidInfo;

    final body = {
      'enroll_token':        enrollToken,
      'udid':                udid,
      'device_name':         name,
      'model':               model,
      'os_version':          posture.osVersion,
      'build_version':       posture.buildVersion,
      'security_patch_level': posture.securityPatchLevel,
      'android_sdk_version': posture.androidSdkVersion,
      'manufacturer':        posture.manufacturer,
      'hardware':            posture.hardware,
      if (ownerEmail != null && ownerEmail.isNotEmpty) 'owner_email': ownerEmail,
      if (fcmToken != null && fcmToken.isNotEmpty) 'push_token': fcmToken,
      // Posture snapshot at enrollment time
      'is_encrypted':        posture.isEncrypted,
      'has_passcode':        posture.hasPasscode,
      'is_rooted':           posture.isRooted,
      'developer_mode_on':   posture.developerModeOn,
      'usb_debugging_enabled': posture.usbDebuggingEnabled,
      'unknown_sources_enabled': posture.unknownSourcesEnabled,
      'battery_level':       posture.batteryLevel,
      'network_type':        posture.networkType,
      'storage_total_gb':    posture.storageTotalGb,
      'storage_free_gb':     posture.storageFreeGb,
      'ram_total_mb':        posture.ramTotalMb,
      // Build fingerprint for forensic tracing
      'build_fingerprint':   androidInfo.fingerprint,
    };

    final result = await client.post('/api/mdm/self-enroll', body);

    await SecureStore.saveCredentials(
      serverUrl:  baseUrl,
      agentToken: result['agent_token'] as String,
      deviceId:   result['device_id'] as int,
      agentId:    result['agent_id'] as int,
      apiKey:     apiKey,
    );
  }

  static Future<void> unenroll() => SecureStore.clear();
}
