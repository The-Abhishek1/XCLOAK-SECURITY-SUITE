package com.xcloak.agent

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

// Native device-posture signals that must go through real Android APIs, not
// a shelled-out CLI command. dumpsys/settings require shell/system UID —
// they throw SecurityException or "Permission Denial" for a regular app's
// own process on every real device (confirmed via `adb shell run-as`), so
// posture_collector.dart's previous Process.run-based checks for these
// fields silently and permanently returned defaults (-1 / false) in
// production. The APIs below are the actual documented, permission-free (or
// already-granted-permission) way a normal app reads this data.
private const val POSTURE_CHANNEL = "xcloak.agent/posture"

class MainActivity : FlutterActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        createNotificationChannel()
        super.onCreate(savedInstanceState)
    }

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, POSTURE_CHANNEL)
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    "getBatteryInfo" -> result.success(getBatteryInfo())
                    "getDeveloperOptionsEnabled" -> result.success(getDeveloperOptionsEnabled())
                    "getAdbEnabled" -> result.success(getAdbEnabled())
                    "getUnknownSourcesEnabled" -> result.success(getUnknownSourcesEnabled())
                    else -> result.notImplemented()
                }
            }
    }

    // BatteryManager's sticky-intent read requires no permission and works
    // on every Android version — this is the standard, correct API dumpsys
    // battery was (incorrectly) standing in for.
    private fun getBatteryInfo(): Map<String, Any> {
        val filter = IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        val batteryStatus: Intent? = registerReceiver(null, filter)
        val level = batteryStatus?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryStatus?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val status = batteryStatus?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1
        val pct = if (level >= 0 && scale > 0) ((level * 100) / scale) else -1
        val charging = status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL
        return mapOf("level" to pct, "charging" to charging)
    }

    // Settings.Global is readable by any app via ContentResolver without any
    // permission — only the "settings" shell CLI tool itself requires
    // shell/system UID, which is what the old Process.run approach hit.
    private fun getDeveloperOptionsEnabled(): Boolean {
        return try {
            Settings.Global.getInt(
                contentResolver, Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0
            ) == 1
        } catch (_: Exception) {
            false
        }
    }

    private fun getAdbEnabled(): Boolean {
        return try {
            Settings.Global.getInt(contentResolver, Settings.Global.ADB_ENABLED, 0) == 1
        } catch (_: Exception) {
            false
        }
    }

    // API 26+: "install from unknown sources" became a per-app grant, not a
    // single global toggle — canRequestPackageInstalls() is the real,
    // documented per-app check, and a more accurate signal than the old
    // global setting ever was even when it existed. API <26 falls back to
    // the pre-Oreo global Settings.Secure flag (also ContentResolver-read,
    // no shell needed).
    private fun getUnknownSourcesEnabled(): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                packageManager.canRequestPackageInstalls()
            } else {
                @Suppress("DEPRECATION")
                Settings.Secure.getInt(
                    contentResolver, Settings.Secure.INSTALL_NON_MARKET_APPS, 0
                ) == 1
            }
        } catch (_: Exception) {
            false
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                "xcloak_agent",
                "XCloak Agent",
                NotificationManager.IMPORTANCE_DEFAULT
            ).apply {
                description = "XCloak security agent background service"
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }
}
