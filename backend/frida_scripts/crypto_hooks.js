// Crypto Hooks
// Hooks javax.crypto.Cipher, Mac, and SecretKeyFactory to log algorithm, keys, and data

Java.perform(function () {

  // --- javax.crypto.Cipher ---
  try {
    var Cipher = Java.use('javax.crypto.Cipher');

    Cipher.doFinal.overload('[B').implementation = function (input) {
      var result = this.doFinal(input);
      send({
        hook: 'Cipher.doFinal',
        algorithm: this.getAlgorithm(),
        mode: this.getBlockSize(),
        input_hex: bytesToHex(input),
        output_hex: bytesToHex(result),
        input_utf8: safeUtf8(input),
        output_utf8: safeUtf8(result),
      });
      return result;
    };

    Cipher.doFinal.overload('[B', 'int', 'int').implementation = function (input, offset, len) {
      var result = this.doFinal(input, offset, len);
      send({
        hook: 'Cipher.doFinal(offset,len)',
        algorithm: this.getAlgorithm(),
        input_hex: bytesToHex(input.slice(offset, offset + len)),
        output_hex: bytesToHex(result),
      });
      return result;
    };

    Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
      send({
        hook: 'Cipher.init',
        algorithm: this.getAlgorithm(),
        mode: mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : String(mode),
        key_hex: bytesToHex(key.getEncoded()),
        key_algorithm: key.getAlgorithm(),
      });
      return this.init(mode, key);
    };

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function (mode, key, params) {
      send({
        hook: 'Cipher.init(with params)',
        algorithm: this.getAlgorithm(),
        mode: mode === 1 ? 'ENCRYPT' : mode === 2 ? 'DECRYPT' : String(mode),
        key_hex: bytesToHex(key.getEncoded()),
      });
      return this.init(mode, key, params);
    };
  } catch (e) {
    send({ hook: 'Cipher', error: e.toString() });
  }

  // --- javax.crypto.Mac ---
  try {
    var Mac = Java.use('javax.crypto.Mac');
    Mac.doFinal.overload('[B').implementation = function (input) {
      var result = this.doFinal(input);
      send({
        hook: 'Mac.doFinal',
        algorithm: this.getAlgorithm(),
        input_hex: bytesToHex(input),
        output_hex: bytesToHex(result),
      });
      return result;
    };
  } catch (e) {
    send({ hook: 'Mac', error: e.toString() });
  }

  // --- MessageDigest (hashing) ---
  try {
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.digest.overload('[B').implementation = function (input) {
      var result = this.digest(input);
      send({
        hook: 'MessageDigest.digest',
        algorithm: this.getAlgorithm(),
        input_hex: bytesToHex(input),
        output_hex: bytesToHex(result),
        input_utf8: safeUtf8(input),
      });
      return result;
    };
  } catch (e) {}

  // --- Helpers ---
  function bytesToHex(bytes) {
    if (!bytes) return '';
    try {
      var arr = Java.array('byte', bytes);
      var hex = '';
      for (var i = 0; i < Math.min(arr.length, 256); i++) {
        var b = arr[i] & 0xff;
        hex += ('0' + b.toString(16)).slice(-2);
      }
      return hex + (arr.length > 256 ? '...' : '');
    } catch (e) { return '<error>'; }
  }

  function safeUtf8(bytes) {
    if (!bytes) return '';
    try {
      var String = Java.use('java.lang.String');
      return String.$new(bytes, 'UTF-8');
    } catch (e) { return ''; }
  }

  send({ status: 'Crypto hooks loaded' });
});
