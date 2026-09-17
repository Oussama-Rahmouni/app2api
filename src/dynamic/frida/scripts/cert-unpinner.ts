/**
 * Universal Certificate Unpinner — Frida script (embedded as a string)
 *
 * Mechanisms bypassed:
 *   1. Custom TrustManager              (most apps)
 *   2. OkHttp3 CertificatePinner        (most Android apps)
 *   3. OkHttp3 HostnameVerifier
 *   4. Android NetworkSecurityConfig    (API 24+)
 *   5. Conscrypt TrustManagerImpl       (Android system SSL)
 *   6. HttpsURLConnection default verifier
 *   7. WebViewClient SSL errors
 *   8. TrustKit
 *
 * NOTE: Native-level pinning (Flutter/BoringSSL) is handled by ssl-interceptor.ts
 *
 * Events are emitted via `emit(obj)` — the bridge defines it as a JSON
 * line on stdout when running through the frida CLI.
 */

export const CERT_UNPINNER_SCRIPT = /* javascript */ `
'use strict';

function tryHook(name, fn) {
  try {
    fn();
    emit({ type: 'unpin', method: name });
  } catch (e) {
    const msg = String(e.message || e);
    if (!msg.includes('ClassNotFoundException') && !msg.includes('no implementation found')) {
      emit({ type: 'unpin_warn', method: name, error: msg });
    }
  }
}

Java.perform(function () {

  // ── 1. Accept-all TrustManager ──────────────────────────────
  tryHook('SSLContext.TrustAll', function () {
    const X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    const SSLContext       = Java.use('javax.net.ssl.SSLContext');

    const TrustAll = Java.registerClass({
      name: 'com.app2api.unpin.TrustAll',
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted(chain, authType) {},
        checkServerTrusted(chain, authType) {},
        getAcceptedIssuers() { return []; },
      },
    });

    const ctx = SSLContext.getInstance('TLS');
    ctx.init(null, [TrustAll.$new()], null);
    SSLContext.getDefault.implementation = function () { return ctx; };
  });

  // ── 2. OkHttp3 CertificatePinner ─────────────────────────────
  tryHook('OkHttp3.CertificatePinner', function () {
    const CP = Java.use('okhttp3.CertificatePinner');
    CP.check.overload('java.lang.String', 'java.util.List')
      .implementation = function () {};
    try {
      CP.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;')
        .implementation = function () {};
    } catch (_) {}
  });

  // ── 3. OkHttp3 HostnameVerifier ──────────────────────────────
  tryHook('OkHttp3.HostnameVerifier', function () {
    Java.use('okhttp3.internal.tls.OkHostnameVerifier')
      .verify.overload('java.lang.String', 'javax.net.ssl.SSLSession')
      .implementation = function () { return true; };
  });

  // ── 4. Android NetworkSecurityConfig (API 24+) ────────────────
  tryHook('NetworkSecurityTrustManager', function () {
    Java.use('android.security.net.config.NetworkSecurityTrustManager')
      .checkPins.overload('java.util.List')
      .implementation = function () {};
  });

  // ── 5. Conscrypt — system-level SSL ──────────────────────────
  tryHook('Conscrypt.TrustManagerImpl', function () {
    const TMI = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    TMI.verifyChain.implementation = function (untrustedChain) {
      return untrustedChain;
    };
  });

  // ── 6. HttpsURLConnection hostname verifier ───────────────────
  tryHook('HttpsURLConnection.HostnameVerifier', function () {
    const HV = Java.use('javax.net.ssl.HostnameVerifier');
    const AllowAll = Java.registerClass({
      name: 'com.app2api.unpin.AllowAll',
      implements: [HV],
      methods: { verify(hostname, session) { return true; } },
    });
    Java.use('javax.net.ssl.HttpsURLConnection')
      .setDefaultHostnameVerifier(AllowAll.$new());
  });

  // ── 7. WebViewClient SSL errors ───────────────────────────────
  tryHook('WebViewClient.SSL', function () {
    Java.use('android.webkit.WebViewClient')
      .onReceivedSslError
      .overload('android.webkit.WebView', 'android.webkit.SslErrorHandler', 'android.net.http.SslError')
      .implementation = function (wv, handler) { handler.proceed(); };
  });

  // ── 8. TrustKit ───────────────────────────────────────────────
  tryHook('TrustKit', function () {
    Java.use('com.datatheorem.android.trustkit.pinning.OkHttp3Helper')
      .getTrustManager.implementation = function () { return null; };
  });

  emit({ type: 'status', message: 'cert-unpinner: all hooks applied' });
});
`;
