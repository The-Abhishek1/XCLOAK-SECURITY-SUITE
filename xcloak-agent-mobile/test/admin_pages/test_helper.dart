// Shared setup for the admin-pages live-integration test suite.
//
// These tests call DashboardApi methods directly (the exact same methods
// every admin screen's onPressed/initState calls) against a REAL running
// backend + Postgres — no widget rendering, no device/emulator, no adb.
// This exercises the actual network round-trip and lets us assert on real
// persisted state, which is what a UI tap ultimately has to get right too.
//
// Prerequisites to run this suite:
//   - Backend running on http://localhost:8080 (or set XCLOAK_TEST_URL)
//   - An admin-role API key in XCLOAK_TEST_API_KEY (or the default below,
//     which matches the 'phase-b-device-test' key created during this
//     session's Phase B pass)
//
// Run: flutter test test/admin_pages/
import 'dart:io';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:xcloak_agent/admin/api.dart';

const String testServerUrl = String.fromEnvironment(
  'XCLOAK_TEST_URL',
  defaultValue: 'http://localhost:8080',
);

const String testApiKey = String.fromEnvironment(
  'XCLOAK_TEST_API_KEY',
  defaultValue:
      'xck_4bbbdf0d3eb2580cb6db1c7fda01f170de46b74bd8f9013b232cca289c78cc50',
);

/// flutter_test runs on a plain Dart VM with no real Keystore/Keychain, so
/// flutter_secure_storage's platform channel has no native side to answer
/// it. DashboardApi.loginWithApiKey writes the session there as a side
/// effect — mock the channel as a harmless no-op so that write doesn't hang.
void mockSecureStorage() {
  TestWidgetsFlutterBinding.ensureInitialized();
  // flutter_test installs a fake HttpOverrides that makes every real
  // HttpClient request come back 400 with no actual network call — these
  // tests need the real thing, since the whole point is a live round-trip
  // against the running backend.
  HttpOverrides.global = null;
  const channel =
      MethodChannel('plugins.it_nomads.com/flutter_secure_storage');
  TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
      .setMockMethodCallHandler(channel, (call) async {
    if (call.method == 'readAll') return <String, String>{};
    return null;
  });
}

Future<DashboardApi> testApi() async {
  mockSecureStorage();
  return DashboardApi.loginWithApiKey(testServerUrl, testApiKey);
}
