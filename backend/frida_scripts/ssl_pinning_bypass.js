// SSL Pinning Bypass
// Hooks TrustManager, OkHttp CertificatePinner, and Flutter BoringSSL

Java.perform(function () {

  // --- 1. Bypass TrustManager (javax.net.ssl) ---
  try {
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
      send({ hook: 'TrustManagerImpl.verifyChain', host: host });
      return untrustedChain;
    };
  } catch (e) {}

  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'com.apkanalysis.TrustManager',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function (chain, authType) {},
        checkServerTrusted: function (chain, authType) {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustManager.$new()], null);
    SSLContext.setDefault(ctx);
    send({ hook: 'SSLContext', status: 'patched with permissive TrustManager' });
  } catch (e) {
    send({ hook: 'SSLContext', error: e.toString() });
  }

  // --- 2. OkHttp CertificatePinner ---
  try {
    var CertificatePinner = Java.use('okhttp3.CertificatePinner');
    CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
      send({ hook: 'OkHttp.CertificatePinner.check', hostname: hostname });
    };
    CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, certs) {
      send({ hook: 'OkHttp.CertificatePinner.check (cert array)', hostname: hostname });
    };
  } catch (e) {}

  // --- 3. OkHttp3 older API ---
  try {
    var CertificatePinnerOld = Java.use('com.squareup.okhttp.CertificatePinner');
    CertificatePinnerOld.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
      send({ hook: 'OkHttp2.CertificatePinner.check', hostname: hostname });
    };
  } catch (e) {}

  // --- 4. WebViewClient (WebView SSL errors) ---
  try {
    var WebViewClient = Java.use('android.webkit.WebViewClient');
    WebViewClient.onReceivedSslError.implementation = function (webView, handler, error) {
      send({ hook: 'WebViewClient.onReceivedSslError', error: error.toString() });
      handler.proceed();
    };
  } catch (e) {}

  send({ status: 'SSL pinning bypass loaded' });
});
