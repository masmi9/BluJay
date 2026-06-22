// Audits Android local storage by hooking SharedPreferences (reads + writes),
// SQLiteDatabase (rawQuery + execSQL), and FileOutputStream (path logging).
// All intercepted data is forwarded via send() to BluJay's Frida event stream.

Java.perform(function () {

  // ── SharedPreferences reads ───────────────────────────────────────────────
  try {
    var SP = Java.use('android.app.SharedPreferencesImpl');
    ['getString', 'getInt', 'getLong', 'getFloat', 'getBoolean'].forEach(function (method) {
      SP[method].overloads.forEach(function (overload) {
        overload.implementation = function () {
          var key  = arguments[0] ? arguments[0].toString() : '(null)';
          var ret  = overload.apply(this, arguments);
          send({ type: 'storage_audit', storage: 'SharedPreferences.read', method: method, key: key, value: String(ret) });
          return ret;
        };
      });
    });
    send({ type: 'storage_audit', event: 'SharedPreferences read hooks installed' });
  } catch (e) {
    send({ type: 'storage_audit', event: 'SharedPreferences read hook error: ' + e.message });
  }

  // ── SharedPreferences writes ──────────────────────────────────────────────
  try {
    var SPE = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
    ['putString', 'putInt', 'putLong', 'putFloat', 'putBoolean'].forEach(function (method) {
      SPE[method].overloads.forEach(function (overload) {
        overload.implementation = function () {
          var key   = arguments[0] ? arguments[0].toString() : '(null)';
          var value = arguments.length > 1 ? String(arguments[1]) : '(null)';
          send({ type: 'storage_audit', storage: 'SharedPreferences.write', method: method, key: key, value: value });
          return overload.apply(this, arguments);
        };
      });
    });
    send({ type: 'storage_audit', event: 'SharedPreferences write hooks installed' });
  } catch (e) {
    send({ type: 'storage_audit', event: 'SharedPreferences write hook error: ' + e.message });
  }

  // ── SQLiteDatabase ────────────────────────────────────────────────────────
  try {
    var DB = Java.use('android.database.sqlite.SQLiteDatabase');

    DB.rawQuery.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var sql = arguments[0] ? arguments[0].toString() : '(null)';
        send({ type: 'storage_audit', storage: 'SQLiteDatabase', method: 'rawQuery', sql: sql });
        return overload.apply(this, arguments);
      };
    });

    DB.execSQL.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var sql = arguments[0] ? arguments[0].toString() : '(null)';
        send({ type: 'storage_audit', storage: 'SQLiteDatabase', method: 'execSQL', sql: sql });
        return overload.apply(this, arguments);
      };
    });

    DB.insert.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var table = arguments[0] ? arguments[0].toString() : '(null)';
        send({ type: 'storage_audit', storage: 'SQLiteDatabase', method: 'insert', table: table });
        return overload.apply(this, arguments);
      };
    });

    send({ type: 'storage_audit', event: 'SQLiteDatabase hooks installed' });
  } catch (e) {
    send({ type: 'storage_audit', event: 'SQLiteDatabase hook error: ' + e.message });
  }

  // ── FileOutputStream (internal / external storage writes) ─────────────────
  try {
    var FOS = Java.use('java.io.FileOutputStream');
    FOS.$init.overloads.forEach(function (overload) {
      overload.implementation = function () {
        var path = arguments[0] ? arguments[0].toString() : '(null)';
        if (
          path.indexOf('/data/data/')  !== -1 ||
          path.indexOf('/data/user/')  !== -1 ||
          path.indexOf('/sdcard/')     !== -1 ||
          path.indexOf('/storage/')    !== -1
        ) {
          send({ type: 'storage_audit', storage: 'FileOutputStream', method: 'open', path: path });
        }
        return overload.apply(this, arguments);
      };
    });
    send({ type: 'storage_audit', event: 'FileOutputStream hooks installed' });
  } catch (e) {
    send({ type: 'storage_audit', event: 'FileOutputStream hook error: ' + e.message });
  }

  send({ type: 'storage_audit', event: 'All android_storage_audit hooks active' });
});
