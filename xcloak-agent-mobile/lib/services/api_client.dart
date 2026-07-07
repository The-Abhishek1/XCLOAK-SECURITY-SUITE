import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:math';

import 'package:http/http.dart' as http;

import 'secure_storage.dart';

// HTTP client that injects the agent bearer token and retries transient
// failures with exponential backoff. Non-retriable errors (4xx, 401, 403)
// are surfaced immediately as ApiException without retrying.

const _maxRetries    = 3;
const _baseDelayMs   = 500; // doubles each attempt

class ApiClient {
  final String  baseUrl;
  final String? agentToken;
  final String? cookie;

  ApiClient({required this.baseUrl, this.agentToken, this.cookie});

  static Future<ApiClient> fromStorage() async {
    final url   = await SecureStore.serverUrl()  ?? '';
    final token = await SecureStore.agentToken() ?? '';
    return ApiClient(baseUrl: url, agentToken: token);
  }

  Map<String, String> get _headers => {
        'Content-Type': 'application/json',
        if (agentToken != null && agentToken!.isNotEmpty)
          'Authorization': 'Bearer $agentToken',
        if (cookie != null && cookie!.isNotEmpty)
          'Cookie': cookie!,
      };

  Uri _uri(String path) => Uri.parse('$baseUrl$path');

  Future<dynamic> post(String path, Map<String, dynamic> body) =>
      _withRetry(() => http.post(_uri(path), headers: _headers, body: jsonEncode(body)));

  Future<dynamic> put(String path, Map<String, dynamic> body) =>
      _withRetry(() => http.put(_uri(path), headers: _headers, body: jsonEncode(body)));

  Future<dynamic> get(String path) =>
      _withRetry(() => http.get(_uri(path), headers: _headers));

  Future<dynamic> delete(String path) =>
      _withRetry(() => http.delete(_uri(path), headers: _headers));

  Future<dynamic> patch(String path, Map<String, dynamic> body) =>
      _withRetry(() => http.patch(_uri(path), headers: _headers, body: jsonEncode(body)));

  // ── Retry logic ────────────────────────────────────────────────────────────

  Future<dynamic> _withRetry(Future<http.Response> Function() fn) async {
    final rng = Random();
    for (var attempt = 0; attempt <= _maxRetries; attempt++) {
      try {
        final res = await fn().timeout(const Duration(seconds: 30));
        if (_isRetriable(res.statusCode) && attempt < _maxRetries) {
          await _delay(attempt, rng);
          continue;
        }
        return _decode(res);
      } on SocketException {
        if (attempt >= _maxRetries) rethrow;
        await _delay(attempt, rng);
      } on TimeoutException {
        if (attempt >= _maxRetries) rethrow;
        await _delay(attempt, rng);
      }
    }
  }

  // 5xx and 429 (rate limit) are worth retrying; 4xx are not.
  static bool _isRetriable(int code) =>
      code == 429 || (code >= 500 && code < 600);

  static Future<void> _delay(int attempt, Random rng) async {
    final jitter = rng.nextInt(200); // up to 200 ms jitter
    final ms     = _baseDelayMs * (1 << attempt) + jitter; // 500, 1000, 2000 ms
    await Future.delayed(Duration(milliseconds: ms));
  }

  // ── Response decoding ──────────────────────────────────────────────────────

  dynamic _decode(http.Response res) {
    if (res.statusCode >= 200 && res.statusCode < 300) {
      if (res.body.isEmpty) return <String, dynamic>{};
      try {
        return jsonDecode(res.body);
      } catch (_) {
        return <String, dynamic>{};
      }
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
  final int    statusCode;
  final String message;
  ApiException(this.statusCode, this.message);
  @override
  String toString() => 'ApiException($statusCode): $message';
}
