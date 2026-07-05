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
const _keyApiKey      = 'xcloak_api_key';

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

  static Future<void> clear() => _storage.deleteAll();

  static Future<void> saveApiKey(String key) => _storage.write(key: _keyApiKey, value: key);
  static Future<void> removeApiKey() => _storage.delete(key: _keyApiKey);
}
