/**
 * FridaBridge — Node.js ↔ Frida communication over the frida CLI.
 *
 * The frida npm package is a heavy native dependency, so this bridge drives
 * the `frida` CLI (from frida-tools) instead: scripts are concatenated into
 * one temp file, loaded with `frida -U -p <pid> -l script.js -q`, and every
 * `emit()` call in a script lands on stdout as one JSON line.
 *
 * Requires: frida CLI on PATH + frida-server running on the device.
 */

import { spawn, type ChildProcess } from "node:child_process";
import { createInterface } from "node:readline";
import { writeFile, unlink } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { EventEmitter } from "node:events";
import { createLogger } from "../../logger.js";
import { requireTool, TOOLS } from "../../tools.js";

const log = createLogger("frida-bridge");

// ── Public types ─────────────────────────────────────────────

export interface CapturedRequest {
  id?: number;
  url: string;
  method: string;
  headers: Record<string, string>;
  body: string | null;
  response: {
    status: number;
    headers: Record<string, string>;
    body: string | null;
  } | null;
  source: "okhttp3" | "ssl" | "mitm";
  error?: string;
  timestamp: string;
}

export interface BridgeEvents {
  request: (req: CapturedRequest) => void;
  unpin: (method: string) => void;
  status: (msg: string) => void;
  error: (msg: string) => void;
}

/**
 * Prelude prepended to the combined script. Scripts call emit(obj);
 * each event becomes one JSON line on the frida CLI's stdout.
 */
const EMIT_PRELUDE = /* javascript */ `
'use strict';
function emit(obj) {
  try { console.log(JSON.stringify(obj)); } catch (_) {}
}
`;

/** Concatenate named scripts behind the emit prelude. */
export function buildCombinedScript(scripts: Record<string, string>): string {
  const parts = [EMIT_PRELUDE];
  for (const [name, source] of Object.entries(scripts)) {
    parts.push(`\n// ── script: ${name} ──\ntry {\n${source}\n} catch (e) {\n  emit({ type: 'script_error', script: ${JSON.stringify(name)}, error: String(e.message || e) });\n}\n`);
  }
  return parts.join("\n");
}

// ── Bridge class ─────────────────────────────────────────────

export class FridaBridge extends EventEmitter {
  private process: ChildProcess | null = null;
  private scriptPath: string | null = null;

  declare emit: <K extends keyof BridgeEvents>(event: K, ...args: Parameters<BridgeEvents[K]>) => boolean;
  declare on: <K extends keyof BridgeEvents>(event: K, listener: BridgeEvents[K]) => this;

  /**
   * Attach to a running process on a USB/emulator device and load the
   * combined script. Resolves once the frida CLI process is spawned.
   */
  async attach(pid: number, scripts: Record<string, string>): Promise<void> {
    requireTool("frida", TOOLS.find((t) => t.name === "frida")!.installHint);

    this.scriptPath = join(tmpdir(), `app2api-frida-${Date.now()}.js`);
    await writeFile(this.scriptPath, buildCombinedScript(scripts), "utf-8");

    // -U: USB device, -p: attach to PID, -l: load script, -q: quiet banner.
    // stdin stays open as a pipe — the frida REPL exits on stdin EOF.
    this.process = spawn("frida", ["-U", "-p", String(pid), "-l", this.scriptPath, "-q"], {
      stdio: ["pipe", "pipe", "pipe"],
    });

    const rl = createInterface({ input: this.process.stdout! });
    rl.on("line", (line) => this.routeLine(line));

    this.process.stderr?.on("data", (chunk: Buffer) => {
      const msg = chunk.toString().trim();
      if (msg) log.warn(`frida stderr: ${msg}`);
    });

    this.process.on("close", (code) => {
      log.info(`frida exited: ${code}`);
      this.process = null;
    });

    this.process.on("error", (err) => {
      this.emit("error", err.message);
    });

    log.info(`Attached to PID ${pid} via frida CLI`);
  }

  private routeLine(line: string): void {
    const trimmed = line.trim();
    if (!trimmed.startsWith("{")) return;

    let payload: Record<string, unknown>;
    try {
      payload = JSON.parse(trimmed);
    } catch {
      return;
    }
    if (!payload?.type) return;

    switch (payload.type) {
      case "http_request":
      case "http_error":
        this.emit("request", payload as unknown as CapturedRequest);
        break;

      case "unpin":
        log.info(`Unpinned: ${payload.method}`);
        this.emit("unpin", payload.method as string);
        break;

      case "unpin_warn":
        log.warn(`Unpin warning [${payload.method}]: ${payload.error}`);
        break;

      case "status":
        log.info(`[frida] ${payload.message}`);
        this.emit("status", String(payload.message));
        break;

      case "script_error":
        log.error(`Script ${payload.script} failed: ${payload.error}`);
        this.emit("error", `${payload.script}: ${payload.error}`);
        break;

      default:
        log.debug(`Unknown event type: ${String(payload.type)}`);
    }
  }

  async detach(): Promise<void> {
    if (this.process) {
      this.process.kill("SIGTERM");
      this.process = null;
    }
    if (this.scriptPath) {
      await unlink(this.scriptPath).catch(() => {});
      this.scriptPath = null;
    }
    log.info("Frida session closed");
  }

  isAttached(): boolean {
    return this.process !== null;
  }
}
