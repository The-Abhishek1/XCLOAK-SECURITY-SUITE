import 'package:device_info_plus/device_info_plus.dart';

import 'api_client.dart';
import 'posture_collector.dart';
import 'secure_storage.dart';

class EnrollmentService {
  // Attempts to enroll this device using a server URL and enrollment token.
  // On success the credentials (agent_token, device_id) are persisted in
  // SecureStore and true is returned. Throws ApiException on failure.
  static Future<void> enroll({
    required String serverUrl,
    required String enrollToken,
    String? ownerEmail,
    String? fcmToken,
    String? apiKey,
  }) async {
    final client = ApiClient(baseUrl: serverUrl.replaceAll(RegExp(r'/+$'), ''));

    final udid   = await PostureCollector.deviceUDID();
    final name   = await PostureCollector.deviceName();
    final model  = await PostureCollector.model();
    final posture = await PostureCollector.collect();
    final androidInfo = await DeviceInfoPlugin().androidInfo;

    final body = {
      'enroll_token':    enrollToken,
      'udid':            udid,
      'device_name':     name,
      'model':           model,
      'os_version':      posture.osVersion,
      'build_version':   posture.buildVersion,
      if (ownerEmail != null && ownerEmail.isNotEmpty) 'owner_email': ownerEmail,
      if (fcmToken != null && fcmToken.isNotEmpty) 'push_token': fcmToken,
      'is_encrypted':    posture.isEncrypted,
      'has_passcode':    posture.hasPasscode,
      'is_rooted':       posture.isRooted,
      'developer_mode_on': posture.developerModeOn,
    };

    final result = await client.post('/api/mdm/self-enroll', body);

    await SecureStore.saveCredentials(
      serverUrl:  serverUrl.replaceAll(RegExp(r'/+$'), ''),
      agentToken: result['agent_token'] as String,
      deviceId:   result['device_id'] as int,
      agentId:    result['agent_id'] as int,
      apiKey:     apiKey,
    );
  }

  static Future<void> unenroll() => SecureStore.clear();
}
