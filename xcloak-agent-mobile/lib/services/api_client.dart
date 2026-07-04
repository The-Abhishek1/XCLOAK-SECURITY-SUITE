import 'dart:convert';
import 'package:http/http.dart' as http;

import 'secure_storage.dart';

// HTTP client that automatically injects the agent bearer token and handles
// the base URL. All methods throw on non-2xx responses.

class ApiClient {
  final String baseUrl;
  final String? agentToken;

  ApiClient({required this.baseUrl, this.agentToken});

  static Future<ApiClient> fromStorage() async {
    final url   = await SecureStore.serverUrl()  ?? '';
    final token = await SecureStore.agentToken() ?? '';
    return ApiClient(baseUrl: url, agentToken: token);
  }

  Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (agentToken != null && agentToken!.isNotEmpty)
          'Authorization': 'Bearer $agentToken',
      };

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<Map<String, dynamic>> post(String path, Map<String, dynamic> body) async {
    final res = await http.post(_uri(path), headers: _headers, body: jsonEncode(body));
    return _decode(res);
  }

  Future<Map<String, dynamic>> put(String path, Map<String, dynamic> body) async {
    final res = await http.put(_uri(path), headers: _headers, body: jsonEncode(body));
    return _decode(res);
  }

  Future<Map<String, dynamic>> get(String path) async {
    final res = await http.get(_uri(path), headers: _headers);
    return _decode(res);
  }

  Map<String, dynamic> _decode(http.Response res) {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      final body = jsonDecode(res.body);
      if (body is Map<String, dynamic>) return body;
      return {'data': body};
    }
    final msg = _tryErrorMsg(res.body) ?? 'HTTP ${res.statusCode}';
    throw ApiException(res.statusCode, msg);
  }

  String? _tryErrorMsg(String body) {
    try {
      final j = jsonDecode(body) as Map<String, dynamic>;
      return j['error']?.toString();
    } catch (_) {
      return null;
    }
  }
}

class ApiException implements Exception {
  final int statusCode;
  final String message;
  ApiException(this.statusCode, this.message);
  @override
  String toString() => 'ApiException($statusCode): $message';
}
