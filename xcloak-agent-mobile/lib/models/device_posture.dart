class DevicePosture {
  final String osVersion;
  final String buildVersion;
  final String securityPatchLevel;
  final int androidSdkVersion;
  final String manufacturer;
  final String hardware;
  final bool? isEncrypted;
  final bool? hasPasscode;
  final bool? passcodeCompliant;
  final bool? biometricEnrolled;
  final bool isRooted;
  final bool developerModeOn;
  final bool usbDebuggingEnabled;
  final bool unknownSourcesEnabled;
  final bool vpnActive;
  final int batteryLevel;          // 0–100
  final bool batteryCharging;
  final String networkType;        // wifi / mobile / none / other
  final String wifiSsid;           // empty if not on WiFi
  final double storageTotalGb;
  final double storageFreeGb;
  final int ramTotalMb;
  final String pushToken;

  DevicePosture({
    required this.osVersion,
    required this.buildVersion,
    this.securityPatchLevel = '',
    this.androidSdkVersion = 0,
    this.manufacturer = '',
    this.hardware = '',
    this.isEncrypted,
    this.hasPasscode,
    this.passcodeCompliant,
    this.biometricEnrolled,
    required this.isRooted,
    required this.developerModeOn,
    this.usbDebuggingEnabled = false,
    this.unknownSourcesEnabled = false,
    this.vpnActive = false,
    this.batteryLevel = -1,
    this.batteryCharging = false,
    this.networkType = 'unknown',
    this.wifiSsid = '',
    this.storageTotalGb = 0,
    this.storageFreeGb = 0,
    this.ramTotalMb = 0,
    this.pushToken = '',
  });

  Map<String, dynamic> toJson() => {
        'os_version':           osVersion,
        'build_version':        buildVersion,
        if (securityPatchLevel.isNotEmpty)
          'security_patch_level': securityPatchLevel,
        if (androidSdkVersion > 0)
          'android_sdk_version': androidSdkVersion,
        if (manufacturer.isNotEmpty) 'manufacturer': manufacturer,
        if (hardware.isNotEmpty)     'hardware': hardware,
        if (isEncrypted != null)     'is_encrypted': isEncrypted,
        if (hasPasscode != null)     'has_passcode': hasPasscode,
        if (passcodeCompliant != null) 'passcode_compliant': passcodeCompliant,
        if (biometricEnrolled != null) 'biometric_enrolled': biometricEnrolled,
        'is_rooted':            isRooted,
        'developer_mode_on':    developerModeOn,
        'usb_debugging_enabled': usbDebuggingEnabled,
        'unknown_sources_enabled': unknownSourcesEnabled,
        'vpn_active':           vpnActive,
        if (batteryLevel >= 0)  'battery_level': batteryLevel,
        'battery_charging':     batteryCharging,
        'network_type':         networkType,
        if (wifiSsid.isNotEmpty) 'wifi_ssid': wifiSsid,
        if (storageTotalGb > 0) 'storage_total_gb': storageTotalGb,
        if (storageFreeGb > 0)  'storage_free_gb': storageFreeGb,
        if (ramTotalMb > 0)     'ram_total_mb': ramTotalMb,
        if (pushToken.isNotEmpty) 'push_token': pushToken,
      };
}

class AppInventoryItem {
  final String packageName;
  final String appName;
  final String version;
  final String installer;
  final bool isSystemApp;
  final List<String> dangerousPermissions;

  AppInventoryItem({
    required this.packageName,
    required this.appName,
    required this.version,
    required this.installer,
    this.isSystemApp = false,
    this.dangerousPermissions = const [],
  });

  Map<String, dynamic> toJson() => {
        'package_name': packageName,
        'app_name':     appName,
        'version':      version,
        'installer':    installer,
        'is_system_app': isSystemApp,
        if (dangerousPermissions.isNotEmpty)
          'dangerous_permissions': dangerousPermissions,
      };
}
