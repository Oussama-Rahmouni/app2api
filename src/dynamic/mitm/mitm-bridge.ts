/**
 * MitmBridge — mitmproxy integration.
 *
 * Launches mitmdump as a subprocess with a small Python addon that prints
 * one JSON object per request. Parses stdout and emits typed events.
 *
 * Works alongside Frida: Frida gives structured Java-layer data,
 * mitmproxy catches anything that bypasses it (NDK, WebView, system).
 *
 * Requires: mitmproxy installed (pip install mitmproxy) and the device
 * proxy pointed at host:port (the pipeline handles this via adb).
 */

import { spawn, type ChildProcess } from "node:child_process";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { createInterface } from "node:readline";
import { createLogger } from "../../logger.js";
import { requireTool, TOOLS } from "../../tools.js";
import type { CapturedRequest } from "../frida/frida-bridge.js";

const log = createLogger("mitm-bridge");

// ── mitmproxy Python addon ────────────────────────────────────
// Written to a temp file at runtime — keeps the project pure TS.

const ADDON_SCRIPT = `
import json, gzip
from mitmproxy import http

MAX_BODY = 100 * 1024  # 100 KB

def _read_body(flow_msg):
    try:
        content = flow_msg.content or b""
        if len(content) > MAX_BODY:
            return f"[{len(content)} bytes]"
        enc_header = flow_msg.headers.get("content-encoding", "")
        if "gzip" in enc_header:
            try:
                content = gzip.decompress(content)
            except Exception:
                pass
        return content.decode("utf-8", errors="replace")
    except Exception as e:
        return f"[read error: {e}]"

def response(flow: http.HTTPFlow):
    if not flow.response:
        return
    data = {
        "type": "http_request",
        "source": "mitm",
        "url": flow.request.pretty_url,
        "method": flow.request.method,
        "headers": dict(flow.request.headers),
        "body": _read_body(flow.request),
        "response": {
            "status": flow.response.status_code,
            "headers": dict(flow.response.headers),
            "body": _read_body(flow.response),
        },
        "timestamp": flow.request.timestamp_start,
    }
    print(json.dumps(data), flush=True)
`;

// ── Bridge class ─────────────────────────────────────────────

export interface MitmBridgeOptions {
  host?: string;
  port?: number;
  /** Only emit requests matching these domains */
  domains?: string[];
  /** Ignore requests to these domains */
  ignoreDomains?: string[];
  /** Path to the mitmdump binary. Default: 'mitmdump' */
  mitmdumpPath?: string;
}

export class MitmBridge extends EventEmitter {
  private process: ChildProcess | null = null;
  private addonPath: string | null = null;
  private opts: Required<MitmBridgeOptions>;

  onRequest(cb: (req: CapturedRequest) => void): this { return this.on("request" as never, cb as never); }
  onError(cb: (msg: string) => void): this { return this.on("error" as never, cb as never); }
  onClose(cb: (code: number | null) => void): this { return this.on("close" as never, cb as never); }

  constructor(opts: MitmBridgeOptions = {}) {
    super();
    this.opts = {
      host: opts.host ?? "0.0.0.0",
      port: opts.port ?? 8080,
      domains: opts.domains ?? [],
      ignoreDomains: opts.ignoreDomains ?? [
        "googleapis.com", "gstatic.com", "firebase.com",
        "crashlytics.com", "sentry.io", "facebook.com",
        "doubleclick.net", "googlesyndication.com",
      ],
      mitmdumpPath: opts.mitmdumpPath ?? "mitmdump",
    };
  }

  async start(): Promise<void> {
    requireTool(this.opts.mitmdumpPath, TOOLS.find((t) => t.name === "mitmdump")!.installHint);

    this.addonPath = join(tmpdir(), `app2api-mitm-addon-${Date.now()}.py`);
    await writeFile(this.addonPath, ADDON_SCRIPT, "utf-8");

    const args = [
      "--listen-host", this.opts.host,
      "--listen-port", String(this.opts.port),
      "--ssl-insecure",          // accept upstream certs (device has our CA)
      "--set", "flow_detail=0",  // suppress built-in logging
      "-q",
      "-s", this.addonPath,
    ];

    log.info(`Starting mitmdump on ${this.opts.host}:${this.opts.port}`);

    this.process = spawn(this.opts.mitmdumpPath, args, {
      stdio: ["ignore", "pipe", "pipe"],
    });

    const rl = createInterface({ input: this.process.stdout! });
    rl.on("line", (line) => {
      if (!line.startsWith("{")) return;
      try {
        const data = JSON.parse(line) as CapturedRequest;
        if (this.shouldEmit(data)) {
          this.emit("request", data);
        }
      } catch { /* malformed line */ }
    });

    this.process.stderr?.on("data", (chunk: Buffer) => {
      const msg = chunk.toString().trim();
      if (msg && !msg.includes("Proxy server listening")) {
        log.warn(`mitmdump stderr: ${msg}`);
      }
    });

    this.process.on("close", (code) => {
      log.info(`mitmdump exited: ${code}`);
      this.emit("close", code);
    });

    this.process.on("error", (err) => {
      this.emit("error", err.message);
    });

    // Give it a moment to bind
    await new Promise((r) => setTimeout(r, 800));
    log.info("mitmdump ready");
  }

  private shouldEmit(req: CapturedRequest): boolean {
    try {
      const host = new URL(req.url).hostname;

      if (this.opts.ignoreDomains.some((d) => host.endsWith(d))) return false;
      if (this.opts.domains.length > 0) {
        return this.opts.domains.some((d) => host.endsWith(d));
      }
      return true;
    } catch {
      return true;
    }
  }

  stop(): void {
    if (this.process) {
      this.process.kill("SIGTERM");
      this.process = null;
    }
    if (this.addonPath) {
      unlink(this.addonPath).catch(() => {});
      this.addonPath = null;
    }
    log.info("mitmdump stopped");
  }

  getPort(): number { return this.opts.port; }
  getHost(): string { return this.opts.host; }
}
