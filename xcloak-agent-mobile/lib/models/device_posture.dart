class DevicePosture {
  final String osVersion;
  final String buildVersion;
  final bool? isEncrypted;
  final bool? hasPasscode;
  final bool? passcodeCompliant;
  final bool isRooted;
  final bool developerModeOn;
  final String pushToken;

  DevicePosture({
    required this.osVersion,
    required this.buildVersion,
    this.isEncrypted,
    this.hasPasscode,
    this.passcodeCompliant,
    required this.isRooted,
    required this.developerModeOn,
    this.pushToken = '',
  });

  Map<String, dynamic> toJson() => {
        'os_version': osVersion,
        'build_version': buildVersion,
        if (isEncrypted != null) 'is_encrypted': isEncrypted,
        if (hasPasscode != null) 'has_passcode': hasPasscode,
        if (passcodeCompliant != null) 'passcode_compliant': passcodeCompliant,
        'is_rooted': isRooted,
        'developer_mode_on': developerModeOn,
        if (pushToken.isNotEmpty) 'push_token': pushToken,
      };
}

class AppInventoryItem {
  final String packageName;
  final String appName;
  final String version;
  final String installer;

  AppInventoryItem({
    required this.packageName,
    required this.appName,
    required this.version,
    required this.installer,
  });

  Map<String, dynamic> toJson() => {
        'package_name': packageName,
        'app_name': appName,
        'version': version,
        'installer': installer,
      };
}
