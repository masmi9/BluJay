/**
 * iOS SSL Pinning Bypass
 * Hooks SecTrustEvaluate, SecTrustEvaluateWithError, and SSLHandshake
 * to bypass certificate pinning on iOS.
 *
 * Usage: Load via Frida on a jailbroken iOS device with frida-server running.
 */

if (ObjC.available) {
  // Hook SecTrustEvaluate (deprecated in iOS 15 but still present)
  try {
    const SecTrustEvaluate = Module.findExportByName("Security", "SecTrustEvaluate");
    if (SecTrustEvaluate) {
      Interceptor.replace(SecTrustEvaluate, new NativeCallback(function (trust, result) {
        const resultPtr = ptr(result);
        resultPtr.writeS32(1); // kSecTrustResultProceed
        send({ type: "ssl_bypass", method: "SecTrustEvaluate", status: "bypassed" });
        return 0; // errSecSuccess
      }, 'int', ['pointer', 'pointer']));
    }
  } catch (e) {
    send({ type: "error", message: "SecTrustEvaluate hook failed: " + e.message });
  }

  // Hook SecTrustEvaluateWithError (iOS 12+)
  try {
    const SecTrustEvaluateWithError = Module.findExportByName("Security", "SecTrustEvaluateWithError");
    if (SecTrustEvaluateWithError) {
      Interceptor.replace(SecTrustEvaluateWithError, new NativeCallback(function (trust, error) {
        if (!error.isNull()) {
          error.writePointer(ptr(0));
        }
        send({ type: "ssl_bypass", method: "SecTrustEvaluateWithError", status: "bypassed" });
        return 1; // true
      }, 'bool', ['pointer', 'pointer']));
    }
  } catch (e) {
    send({ type: "error", message: "SecTrustEvaluateWithError hook failed: " + e.message });
  }

  // Hook NSURLSession delegate didReceiveChallenge (common pinning pattern)
  try {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
      const method = ObjC.classes.NSURLSession["- URLSession:didReceiveChallenge:completionHandler:"];
      if (method) {
        Interceptor.attach(method.implementation, {
          onEnter: function (args) {
            const completionHandler = new ObjC.Block(args[4]);
            const NSURLSessionAuthChallengeUseCredential = 0;
            const cred = ObjC.classes.NSURLCredential.credentialForTrust_(args[3]);
            completionHandler.call(NSURLSessionAuthChallengeUseCredential, cred);
            send({ type: "ssl_bypass", method: "NSURLSessionDelegate", status: "bypassed" });
          }
        });
      }
    }
  } catch (e) {
    // NSURLSession patching optional
  }

  send({ type: "log", message: "[iOS SSL Bypass] Hooks installed" });
} else {
  send({ type: "error", message: "Objective-C runtime not available" });
}
