/**
 * iOS Jailbreak Detection Bypass
 * Hooks NSFileManager fileExistsAtPath: and related APIs
 * to hide common jailbreak indicators.
 *
 * Usage: Load via Frida on a jailbroken iOS device with frida-server running.
 */

if (ObjC.available) {
  const JAILBREAK_PATHS = [
    "/Applications/Cydia.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/Applications/blackra1n.app",
    "/Library/MobileSubstrate/MobileSubstrate.dylib",
    "/bin/bash",
    "/bin/sh",
    "/bin/su",
    "/etc/apt",
    "/etc/ssh/sshd_config",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/cycript",
    "/usr/bin/ssh",
    "/usr/bin/sshd",
    "/usr/libexec/ssh-keysign",
    "/usr/libexec/sftp-server",
    "/usr/sbin/sshd",
    "/var/cache/apt",
    "/var/lib/apt",
    "/var/lib/cydia",
    "/var/log/syslog",
    "/var/tmp/cydia.log",
  ];

  // Hook NSFileManager fileExistsAtPath:
  try {
    const fileExistsAtPath = ObjC.classes.NSFileManager["- fileExistsAtPath:"];
    Interceptor.attach(fileExistsAtPath.implementation, {
      onEnter: function (args) {
        this.path = ObjC.Object(args[2]).toString();
      },
      onLeave: function (retval) {
        if (JAILBREAK_PATHS.includes(this.path)) {
          retval.replace(ptr(0)); // return NO
          send({ type: "jailbreak_bypass", method: "fileExistsAtPath", path: this.path });
        }
      }
    });
  } catch (e) {
    send({ type: "error", message: "fileExistsAtPath hook failed: " + e.message });
  }

  // Hook NSFileManager fileExistsAtPath:isDirectory:
  try {
    const fileExistsAtPathIsDir = ObjC.classes.NSFileManager["- fileExistsAtPath:isDirectory:"];
    Interceptor.attach(fileExistsAtPathIsDir.implementation, {
      onEnter: function (args) {
        this.path = ObjC.Object(args[2]).toString();
      },
      onLeave: function (retval) {
        if (JAILBREAK_PATHS.includes(this.path)) {
          retval.replace(ptr(0));
          send({ type: "jailbreak_bypass", method: "fileExistsAtPath:isDirectory:", path: this.path });
        }
      }
    });
  } catch (e) { /* optional */ }

  // Hook canOpenURL for Cydia scheme
  try {
    const canOpenURL = ObjC.classes.UIApplication["- canOpenURL:"];
    Interceptor.attach(canOpenURL.implementation, {
      onEnter: function (args) {
        const url = ObjC.Object(args[2]).toString();
        this.isCydia = url.startsWith("cydia://") || url.startsWith("sileo://");
      },
      onLeave: function (retval) {
        if (this.isCydia) {
          retval.replace(ptr(0));
          send({ type: "jailbreak_bypass", method: "canOpenURL", scheme: "cydia/sileo" });
        }
      }
    });
  } catch (e) { /* optional */ }

  send({ type: "log", message: "[iOS Jailbreak Bypass] Hooks installed" });
} else {
  send({ type: "error", message: "Objective-C runtime not available" });
}
