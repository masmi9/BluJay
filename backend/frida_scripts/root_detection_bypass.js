// Root Detection Bypass
// Hooks RootBeer, SafetyNet, file checks, Build.TAGS, and common su/busybox checks

Java.perform(function () {

  // --- 1. RootBeer ---
  try {
    var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
    RootBeer.isRooted.implementation = function () {
      send({ hook: 'RootBeer.isRooted', result: false });
      return false;
    };
    RootBeer.isRootedWithoutBusyBoxCheck.implementation = function () {
      send({ hook: 'RootBeer.isRootedWithoutBusyBoxCheck', result: false });
      return false;
    };
  } catch (e) {}

  // --- 2. Build.TAGS ---
  try {
    var Build = Java.use('android.os.Build');
    Build.TAGS.value = 'release-keys';
    send({ hook: 'Build.TAGS', patched: 'release-keys' });
  } catch (e) {}

  // --- 3. File existence checks (su, busybox, magisk) ---
  try {
    var File = Java.use('java.io.File');
    var suspicious = [
      '/su', '/system/bin/su', '/system/xbin/su',
      '/sbin/su', '/system/su', '/system/bin/.ext/.su',
      '/system/usr/we-need-root/su-backup',
      '/data/local/xbin/su', '/data/local/bin/su',
      '/data/local/su', '/system/app/Superuser.apk',
      '/system/app/SuperSU.apk', '/system/xbin/busybox',
      '/data/adb/magisk', '/sbin/.magisk',
    ];
    File.exists.implementation = function () {
      var path = this.getAbsolutePath();
      if (suspicious.indexOf(path) !== -1) {
        send({ hook: 'File.exists', path: path, spoofed: false });
        return false;
      }
      return this.exists();
    };
  } catch (e) {}

  // --- 4. Runtime.exec (su command execution check) ---
  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (cmd && (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1)) {
        send({ hook: 'Runtime.exec', cmd: cmd, blocked: true });
        throw Java.use('java.io.IOException').$new('Permission denied');
      }
      return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function (cmds) {
      if (cmds && cmds.length > 0 && cmds[0].indexOf('su') !== -1) {
        send({ hook: 'Runtime.exec[]', cmd: cmds[0], blocked: true });
        throw Java.use('java.io.IOException').$new('Permission denied');
      }
      return this.exec(cmds);
    };
  } catch (e) {}

  // --- 5. SafetyNet (Google Play) ---
  try {
    var SafetyNetApi = Java.use('com.google.android.gms.safetynet.SafetyNetApi');
    send({ hook: 'SafetyNet', status: 'hooks loaded (dynamic patching required per app)' });
  } catch (e) {}

  send({ status: 'Root detection bypass loaded' });
});
