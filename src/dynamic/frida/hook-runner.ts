/**
 * HookRunner — assembles the Frida scripts in the right order and
 * collects what they capture.
 *
 * Script order matters:
 *   1. cert-unpinner      — must fire before any SSL connections are made
 *   2. okhttp-interceptor — hooks Builder.build() for all future clients
 *   3. ssl-interceptor    — fallback for Flutter / native HTTP
 */

import type { FridaBridge, CapturedRequest } from "./frida-bridge.js";
import { CERT_UNPINNER_SCRIPT } from "./scripts/cert-unpinner.js";
import { OKHTTP_INTERCEPTOR_SCRIPT } from "./scripts/okhttp-interceptor.js";
import { SSL_INTERCEPTOR_SCRIPT } from "./scripts/ssl-interceptor.js";
import { createLogger } from "../../logger.js";

const log = createLogger("hook-runner");

export interface HookRunnerOptions {
  /** Load SSL native hooks (needed for Flutter). Default: true */
  ssl?: boolean;
}

export class HookRunner {
  private bridge: FridaBridge;
  private captures: CapturedRequest[] = [];
  private unpinnedMethods: string[] = [];

  constructor(bridge: FridaBridge) {
    this.bridge = bridge;
    this.setupListeners();
  }

  private setupListeners(): void {
    this.bridge.on("request", (req) => {
      this.captures.push(req);
      const status = req.response?.status ?? req.error ?? "...";
      log.info(`${req.method} ${req.url} → ${status}`);
    });

    this.bridge.on("unpin", (method) => {
      this.unpinnedMethods.push(method);
    });

    this.bridge.on("error", (msg) => {
      log.error(`Bridge error: ${msg}`);
    });
  }

  /** The scripts to load, in order. cert-unpinner always first. */
  buildScripts(opts: HookRunnerOptions = {}): Record<string, string> {
    const { ssl = true } = opts;
    const scripts: Record<string, string> = {
      "cert-unpinner": CERT_UNPINNER_SCRIPT,
      "okhttp-interceptor": OKHTTP_INTERCEPTOR_SCRIPT,
    };
    if (ssl) {
      scripts["ssl-interceptor"] = SSL_INTERCEPTOR_SCRIPT;
    }
    return scripts;
  }

  // ── Results ──────────────────────────────────────────────────

  getCaptures(): CapturedRequest[] {
    return [...this.captures];
  }

  getUnpinnedMethods(): string[] {
    return [...this.unpinnedMethods];
  }

  /** Unique endpoints seen — deduplicated by method+URL */
  getUniqueEndpoints(): Array<{ url: string; method: string; count: number; lastStatus: number | null }> {
    const map = new Map<string, { url: string; method: string; count: number; lastStatus: number | null }>();

    for (const req of this.captures) {
      const key = `${req.method}::${req.url}`;
      const existing = map.get(key);
      if (existing) {
        existing.count++;
        existing.lastStatus = req.response?.status ?? existing.lastStatus;
      } else {
        map.set(key, {
          url: req.url,
          method: req.method,
          count: 1,
          lastStatus: req.response?.status ?? null,
        });
      }
    }

    return [...map.values()].sort((a, b) => b.count - a.count);
  }

  /** Deduplicated auth headers seen across all requests */
  getAuthHeaders(): Record<string, string> {
    const auth: Record<string, string> = {};
    const authKeys = ["authorization", "x-api-key", "api-key", "x-auth-token", "x-access-token"];

    for (const req of this.captures) {
      for (const key of authKeys) {
        if (req.headers[key] && !auth[key]) {
          auth[key] = req.headers[key];
        }
      }
    }

    return auth;
  }

  clear(): void {
    this.captures = [];
    this.unpinnedMethods = [];
  }
}
