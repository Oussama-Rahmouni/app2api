/**
 * OkHttp3 Network Interceptor — Frida script (embedded as a string)
 *
 * Strategy: hook OkHttpClient.Builder.build() and inject our own
 * NetworkInterceptor into every OkHttpClient the app creates.
 * NetworkInterceptors run AFTER all application interceptors — meaning
 * all auth headers, tokens, and signatures are already applied.
 *
 * Covers: sync (execute) + async (enqueue) — both go through the chain.
 * Covers: Retrofit, Apollo GraphQL, anything built on OkHttp3.
 */

export const OKHTTP_INTERCEPTOR_SCRIPT = /* javascript */ `
'use strict';

const MAX_BODY_BYTES = 100 * 1024; // 100 KB cap
let reqCount = 0;

// ── Helpers ──────────────────────────────────────────────────
function headersToObj(headers) {
  const out = {};
  try {
    const size = headers.size();
    for (let i = 0; i < size; i++) {
      out[headers.name(i).toLowerCase()] = headers.value(i);
    }
  } catch (_) {}
  return out;
}

function readRequestBody(body) {
  if (body === null) return null;
  try {
    const Buffer = Java.use('okio.Buffer');
    const buf = Buffer.$new();
    body.writeTo(buf);
    const clone = buf.clone();
    const size = clone.size().toNumber ? clone.size().toNumber() : Number(clone.size());
    if (size > MAX_BODY_BYTES) return '[' + size + ' bytes]';
    return clone.readUtf8();
  } catch (e) {
    return '[req body error: ' + e.message + ']';
  }
}

function readResponseBody(response) {
  // Returns { body: string|null, newResponse: Response }
  const ResponseBody = Java.use('okhttp3.ResponseBody');
  const bodySource = response.body();

  if (bodySource === null) {
    return { body: null, newResponse: response };
  }

  try {
    const contentType = bodySource.contentType();
    const bytes = bodySource.bytes(); // consumes the stream
    const size = bytes.length;
    let text;
    if (size === 0) {
      text = '';
    } else if (size > MAX_BODY_BYTES) {
      text = '[' + size + ' bytes - truncated]';
    } else {
      try {
        text = Java.use('java.lang.String').$new(bytes, 'UTF-8');
      } catch (_) {
        text = '[binary ' + size + ' bytes]';
      }
    }

    // Restore the body so the app can still read it
    const newBody = ResponseBody.create(contentType, bytes);
    const newResponse = response.newBuilder().body(newBody).build();
    return { body: text, newResponse };
  } catch (e) {
    return { body: '[resp body error: ' + e.message + ']', newResponse: response };
  }
}

// ── Main hook ────────────────────────────────────────────────
Java.perform(function () {
  const Interceptor = Java.use('okhttp3.Interceptor');

  // Register the interceptor class once — reused for all OkHttpClient instances
  const App2ApiInterceptor = Java.registerClass({
    name: 'com.app2api.NetworkCaptureInterceptor',
    implements: [Interceptor],
    methods: {
      intercept(chain) {
        const request = chain.request();
        const url     = request.url().toString();
        const method  = request.method();
        const reqHdrs = headersToObj(request.headers());
        const reqBody = readRequestBody(request.body());

        // Forward the request
        let response;
        try {
          response = chain.proceed(request);
        } catch (e) {
          emit({
            type: 'http_error',
            source: 'okhttp3',
            id: ++reqCount,
            url, method,
            headers: reqHdrs,
            body: reqBody,
            error: String(e.message),
            timestamp: new Date().toISOString(),
          });
          throw e;
        }

        const status   = response.code();
        const respHdrs = headersToObj(response.headers());
        const { body: respBody, newResponse } = readResponseBody(response);

        emit({
          type: 'http_request',
          source: 'okhttp3',
          id: ++reqCount,
          url,
          method,
          headers: reqHdrs,
          body: reqBody,
          response: { status, headers: respHdrs, body: respBody },
          timestamp: new Date().toISOString(),
        });

        return newResponse;
      },
    },
  });

  // Inject into every OkHttpClient built via Builder
  const Builder = Java.use('okhttp3.OkHttpClient$Builder');
  Builder.build.implementation = function () {
    this.addNetworkInterceptor(App2ApiInterceptor.$new());
    return this.build();
  };

  emit({ type: 'status', message: 'okhttp-interceptor: hooked OkHttpClient.Builder.build()' });
});
`;
