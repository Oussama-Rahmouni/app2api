/**
 * SSL Native Interceptor — Frida script (embedded as a string)
 *
 * The native fallback: hooks SSL_read / SSL_write at the BoringSSL/OpenSSL
 * level. Works on everything — Flutter (Dart HTTP), NDK code, React Native
 * fetch — anything that uses TLS regardless of the Java layer.
 *
 * Operates below certificate pinning: data here is already decrypted.
 *
 * Buffers per SSL session, reconstructs HTTP requests/responses from the
 * plaintext stream, emits structured events to the bridge.
 */

export const SSL_INTERCEPTOR_SCRIPT = /* javascript */ `
'use strict';

const MAX_BUF   = 256 * 1024; // 256 KB per session buffer before flush
const MAX_EMIT  = 100 * 1024; // 100 KB max emitted body

// per-session state: { tx: outgoing/request, rx: incoming/response }
const sessions = new Map();

function getSession(sslPtr) {
  const key = sslPtr.toString();
  if (!sessions.has(key)) sessions.set(key, { tx: '', rx: '', host: '' });
  return sessions.get(key);
}

function bufToString(buf, n) {
  try {
    return Memory.readUtf8String(buf, n);
  } catch (_) {
    return '[binary]';
  }
}

// ── HTTP reconstruction ──────────────────────────────────────
const REQ_LINE  = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|CONNECT|TRACE) ([^\\s]+) HTTP\\//;
const RESP_LINE = /^HTTP\\/[\\d.]+ (\\d{3})/;
const HEADER_END = '\\r\\n\\r\\n';

function parseHTTPHeaders(raw) {
  const headerEnd = raw.indexOf(HEADER_END);
  if (headerEnd === -1) return null;

  const headerBlock = raw.substring(0, headerEnd);
  const lines = headerBlock.split('\\r\\n');
  const firstLine = lines[0];
  const headers = {};

  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(':');
    if (colon > 0) {
      const k = lines[i].substring(0, colon).trim().toLowerCase();
      const v = lines[i].substring(colon + 1).trim();
      headers[k] = v;
    }
  }

  return { firstLine, headers, headerEnd, bodyStart: headerEnd + 4 };
}

function tryEmitRequest(session, sslPtr) {
  const raw = session.tx;
  const parsed = parseHTTPHeaders(raw);
  if (!parsed) return;

  const match = REQ_LINE.exec(parsed.firstLine);
  if (!match) return;

  const method = match[1];
  const path   = match[2];
  const host   = parsed.headers['host'] || session.host || '';
  const url    = host ? 'https://' + host + path : path;

  const contentLength = parseInt(parsed.headers['content-length'] || '0', 10);
  const bodyEnd = parsed.bodyStart + contentLength;

  if (raw.length < bodyEnd && contentLength > 0) return; // incomplete

  const body = raw.substring(parsed.bodyStart, bodyEnd) || null;

  emit({
    type: 'http_request',
    source: 'ssl',
    url, method,
    headers: parsed.headers,
    body: body && body.length > MAX_EMIT ? '[' + body.length + ' bytes]' : body,
    timestamp: new Date().toISOString(),
  });

  session.tx = raw.substring(bodyEnd);
}

function tryEmitResponse(session) {
  const raw = session.rx;
  const parsed = parseHTTPHeaders(raw);
  if (!parsed) return;

  const match = RESP_LINE.exec(parsed.firstLine);
  if (!match) return;

  const status = parseInt(match[1], 10);
  const contentLength = parseInt(parsed.headers['content-length'] || '-1', 10);

  if (contentLength >= 0) {
    if (raw.length < parsed.bodyStart + contentLength) return; // incomplete
  }

  const bodyRaw = contentLength >= 0
    ? raw.substring(parsed.bodyStart, parsed.bodyStart + contentLength)
    : raw.substring(parsed.bodyStart);

  emit({
    type: 'ssl_response',
    source: 'ssl',
    status,
    headers: parsed.headers,
    body: bodyRaw.length > MAX_EMIT ? '[' + bodyRaw.length + ' bytes]' : bodyRaw,
    timestamp: new Date().toISOString(),
  });

  session.rx = contentLength >= 0
    ? raw.substring(parsed.bodyStart + contentLength)
    : '';
}

// ── Native hooks ─────────────────────────────────────────────
function findSSLLib() {
  const candidates = [
    'libssl.so', 'libssl.so.3', 'libssl.so.1.1',
    'libboringssl.so', 'libconscrypt_jni.so',
  ];
  for (const name of candidates) {
    if (Process.findModuleByName(name)) return name;
  }
  return null;
}

const sslLib = findSSLLib();

if (!sslLib) {
  emit({ type: 'status', message: 'ssl-interceptor: no SSL native lib found — disabled' });
} else {
  const ssl_read  = Module.findExportByName(sslLib, 'SSL_read');
  const ssl_write = Module.findExportByName(sslLib, 'SSL_write');

  if (ssl_read) {
    Interceptor.attach(ssl_read, {
      onEnter(args) {
        this.ssl = args[0];
        this.buf = args[1];
      },
      onLeave(retval) {
        const n = retval.toInt32();
        if (n <= 0) return;
        const text = bufToString(this.buf, n);
        const s = getSession(this.ssl);
        s.rx += text;
        if (s.rx.length > MAX_BUF) s.rx = s.rx.slice(-MAX_BUF); // rolling window
        tryEmitResponse(s);
      },
    });
  }

  if (ssl_write) {
    Interceptor.attach(ssl_write, {
      onEnter(args) {
        const ssl = args[0];
        const buf = args[1];
        const n   = args[2].toInt32();
        if (n <= 0) return;
        const text = bufToString(buf, n);
        const s = getSession(ssl);
        s.tx += text;
        if (s.tx.length > MAX_BUF) s.tx = s.tx.slice(-MAX_BUF);
        tryEmitRequest(s, ssl);
      },
    });
  }

  emit({ type: 'status', message: 'ssl-interceptor: hooked SSL_read/write on ' + sslLib });
}
`;
