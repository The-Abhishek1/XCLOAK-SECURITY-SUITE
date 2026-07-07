import 'package:flutter_secure_storage/flutter_secure_storage.dart';

// Thin wrapper around FlutterSecureStorage so the rest of the codebase never
// imports the package directly — makes it easy to swap implementations.

const _storage = FlutterSecureStorage(
  aOptions: AndroidOptions(encryptedSharedPreferences: true),
);

const _keyServerUrl   = 'xcloak_server_url';
const _keyAgentToken  = 'xcloak_agent_token';
const _keyDeviceId    = 'xcloak_device_id';
const _keyAgentId     = 'xcloak_agent_id';
const _keyEnrolled    = 'xcloak_enrolled';
const _keyApiKey      = 'xcloak_api_key';  // legacy — kept for backward compat
const _keyAdminCookie    = 'xcloak_admin_cookie';
const _keyAdminEmail     = 'xcloak_admin_email';
const _keyAdminRole      = 'xcloak_admin_role';
const _keyPendingMessage = 'xcloak_pending_message';

class SecureStore {
  static Future<void> saveCredentials({
    required String serverUrl,
    required String agentToken,
    required int deviceId,
    required int agentId,
    String? apiKey,
  }) async {
    await Future.wait([
      _storage.write(key: _keyServerUrl,  value: serverUrl),
      _storage.write(key: _keyAgentToken, value: agentToken),
      _storage.write(key: _keyDeviceId,   value: deviceId.toString()),
      _storage.write(key: _keyAgentId,    value: agentId.toString()),
      _storage.write(key: _keyEnrolled,   value: 'true'),
      if (apiKey != null && apiKey.isNotEmpty)
        _storage.write(key: _keyApiKey,   value: apiKey),
    ]);
  }

  static Future<bool> isEnrolled() async {
    final v = await _storage.read(key: _keyEnrolled);
    return v == 'true';
  }

  static Future<String?> serverUrl()  => _storage.read(key: _keyServerUrl);
  static Future<String?> agentToken() => _storage.read(key: _keyAgentToken);
  static Future<String?> apiKey()     => _storage.read(key: _keyApiKey);
  static Future<int?> deviceId() async {
    final v = await _storage.read(key: _keyDeviceId);
    return v != null ? int.tryParse(v) : null;
  }
  static Future<int?> agentId() async {
    final v = await _storage.read(key: _keyAgentId);
    return v != null ? int.tryParse(v) : null;
  }

  // Admin console session (cookie-based, role-verified)
  static Future<void> saveAdminSession({
    required String cookie,
    required String email,
    required String role,
  }) async {
    await Future.wait([
      _storage.write(key: _keyAdminCookie, value: cookie),
      _storage.write(key: _keyAdminEmail,  value: email),
      _storage.write(key: _keyAdminRole,   value: role),
    ]);
  }

  static Future<String?> adminCookie() => _storage.read(key: _keyAdminCookie);
  static Future<String?> adminEmail()  => _storage.read(key: _keyAdminEmail);
  static Future<String?> adminRole()   => _storage.read(key: _keyAdminRole);

  static Future<void> clearAdminSession() async {
    await Future.wait([
      _storage.delete(key: _keyAdminCookie),
      _storage.delete(key: _keyAdminEmail),
      _storage.delete(key: _keyAdminRole),
    ]);
  }

  static Future<void> clear() => _storage.deleteAll();

  static Future<void> saveApiKey(String key) => _storage.write(key: _keyApiKey, value: key);
  static Future<void> removeApiKey() => _storage.delete(key: _keyApiKey);

  // Token rotation
  static Future<void> storeAgentToken(String token) =>
      _storage.write(key: _keyAgentToken, value: token);

  // Pending server-pushed message shown on next app open
  static Future<void> storePendingMessage(String text) =>
      _storage.write(key: _keyPendingMessage, value: text);
  static Future<String?> pendingMessage() =>
      _storage.read(key: _keyPendingMessage);
  static Future<void> clearPendingMessage() =>
      _storage.delete(key: _keyPendingMessage);
}
