/**
 * DynamicExtractor — full dynamic capture pipeline.
 *
 * Input:  APK path + target domain
 * Output: captured requests, unique endpoints, auth headers, common headers
 *
 * Pipeline:
 *   1. Install the APK on the device
 *   2. Start frida-server (if not running)
 *   3. Launch the app
 *   4. Attach Frida + load hooks (cert unpinning, OkHttp, native SSL)
 *   5. Start mitmproxy (parallel capture layer)
 *   6. Wait for traffic (configurable)
 *   7. Collect + deduplicate
 *   8. Return a structured ExtractionResult
 *
 * Requirements: rooted emulator (or rooted device), frida-server, mitmproxy,
 * and the mitmproxy CA installed on the device.
 */

import { writeFile, mkdir } from "node:fs/promises";
import { join } from "node:path";
import { ADB } from "../adb.js";
import { FridaBridge, type CapturedRequest } from "../frida/frida-bridge.js";
import { HookRunner } from "../frida/hook-runner.js";
import { MitmBridge } from "../mitm/mitm-bridge.js";
import { createLogger } from "../../logger.js";

const log = createLogger("dynamic-extractor");

// ── Types ────────────────────────────────────────────────────

export interface EndpointSpec {
  url: string;
  method: string;
  count: number;
  lastStatus: number | null;
  exampleHeaders: Record<string, string>;
  exampleBody: string | null;
}

export interface ExtractionResult {
  domain: string;
  packageName: string;
  extractedAt: string;
  durationMs: number;

  /** All raw captured requests */
  requests: CapturedRequest[];
  /** Deduplicated unique endpoints */
  endpoints: EndpointSpec[];
  /** Auth headers seen across all requests */
  authHeaders: Record<string, string>;
  /** Consistent headers present on most requests (UA, platform, version...) */
  commonHeaders: Record<string, string>;

  stats: {
    totalRequests: number;
    uniqueEndpoints: number;
    unpinnedMethods: string[];
  };
}

export interface ExtractorOptions {
  /** How long to capture traffic. Default: 60s */
  captureMs?: number;
  /** Device serial (auto-selects first available if omitted) */
  deviceSerial?: string;
  /** Path to a frida-server binary to push (skips if already running) */
  fridaServerPath?: string;
  /** Enable the mitmproxy capture layer. Default: true */
  mitm?: boolean;
  /** mitmproxy port. Default: 8080 */
  mitmPort?: number;
  /** Enable SSL native hooks (needed for Flutter). Default: true */
  ssl?: boolean;
  /** Save raw results to the output dir. Default: true */
  save?: boolean;
  outputDir?: string;
}

// ── Main function ─────────────────────────────────────────────

export async function extractDynamic(
  apkPath: string,
  domain: string,
  opts: ExtractorOptions = {},
): Promise<ExtractionResult> {
  const {
    captureMs = 60_000,
    deviceSerial,
    fridaServerPath,
    mitm: enableMitm = true,
    mitmPort = 8080,
    ssl = true,
    save: saveResult = true,
    outputDir = "./output/dynamic",
  } = opts;

  const start = Date.now();

  // ── 1. Connect to device ──────────────────────────────────────
  const adb = deviceSerial ? new ADB(deviceSerial) : ADB.firstAvailable();
  log.info(`Device: ${adb.getDeviceModel()} Android ${adb.getAndroidVersion()} [${adb.getArchitecture()}]`);

  // ── 2. Install APK ────────────────────────────────────────────
  log.info(`Installing: ${apkPath}`);
  let packageName: string;
  try {
    packageName = adb.getPackageNameFromApk(apkPath);
  } catch {
    packageName = domain.replace(/\./g, "_"); // fallback
    log.warn(`Cannot read package name from APK (aapt missing?), using: ${packageName}`);
  }
  adb.installApk(apkPath);

  // ── 3. frida-server ───────────────────────────────────────────
  if (fridaServerPath) {
    adb.setupFridaServer(fridaServerPath);
  }
  if (!adb.isFridaServerRunning()) {
    adb.startFridaServer();
  }

  // ── 4. Launch app ─────────────────────────────────────────────
  adb.stopApp(packageName); // clean state
  await new Promise((r) => setTimeout(r, 500));
  adb.startApp(packageName);

  // ── 5. mitmproxy (parallel layer) ─────────────────────────────
  let mitmBridge: MitmBridge | null = null;
  const mitmCaptures: CapturedRequest[] = [];

  if (enableMitm) {
    mitmBridge = new MitmBridge({
      port: mitmPort,
      domains: [domain],
    });
    mitmBridge.onRequest((req) => {
      mitmCaptures.push(req);
      log.debug(`[mitm] ${req.method} ${req.url} → ${req.response?.status}`);
    });
    mitmBridge.onError((msg) => log.warn(`mitm error: ${msg}`));

    // Route device traffic through mitmproxy on the host
    adb.reversePort(mitmPort); // device:8080 → host:8080
    adb.setProxy("127.0.0.1", mitmPort);

    await mitmBridge.start();
  }

  // ── 6. Attach Frida + load hooks ──────────────────────────────
  const bridge = new FridaBridge();

  const proc = adb.waitForProcess(packageName, 15_000);
  log.info(`Process: ${proc.name} (PID ${proc.pid})`);

  const runner = new HookRunner(bridge);
  await bridge.attach(proc.pid, runner.buildScripts({ ssl }));

  // ── 7. Wait for traffic ───────────────────────────────────────
  log.info(`Capturing traffic for ${captureMs / 1000}s... (use the app now)`);
  await new Promise((r) => setTimeout(r, captureMs));

  // ── 8. Cleanup ────────────────────────────────────────────────
  await bridge.detach();

  if (mitmBridge) {
    mitmBridge.stop();
    adb.clearProxy();
    adb.removeReverse(mitmPort);
  }

  adb.stopApp(packageName);

  // ── 9. Build results ──────────────────────────────────────────
  const fridaCaptures = runner.getCaptures();
  const allCaptures = deduplicateRequests([...fridaCaptures, ...mitmCaptures]);

  const uniqueEndpoints = buildEndpointSpecs(allCaptures, domain);
  const authHeaders = runner.getAuthHeaders();
  const commonHeaders = findCommonHeaders(allCaptures);

  const result: ExtractionResult = {
    domain,
    packageName,
    extractedAt: new Date().toISOString(),
    durationMs: Date.now() - start,

    requests: allCaptures,
    endpoints: uniqueEndpoints,
    authHeaders,
    commonHeaders,

    stats: {
      totalRequests: allCaptures.length,
      uniqueEndpoints: uniqueEndpoints.length,
      unpinnedMethods: runner.getUnpinnedMethods(),
    },
  };

  // ── 10. Save ──────────────────────────────────────────────────
  if (saveResult) {
    await mkdir(outputDir, { recursive: true });
    const filename = `${domain}-${Date.now()}.json`;
    await writeFile(join(outputDir, filename), JSON.stringify(result, null, 2), "utf-8");
    log.info(`Results saved: ${join(outputDir, filename)}`);
  }

  log.info(`Done — ${result.stats.totalRequests} requests, ${result.stats.uniqueEndpoints} unique endpoints`);

  return result;
}

// ── Helpers ──────────────────────────────────────────────────

function deduplicateRequests(requests: CapturedRequest[]): CapturedRequest[] {
  // Drop exact URL+method+body duplicates captured by both Frida and mitmproxy
  const seen = new Set<string>();
  return requests.filter((req) => {
    const key = `${req.method}::${req.url}::${req.body ?? ""}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function buildEndpointSpecs(requests: CapturedRequest[], targetDomain: string): EndpointSpec[] {
  const map = new Map<string, EndpointSpec>();

  for (const req of requests) {
    try {
      const host = new URL(req.url).hostname;
      if (!host.endsWith(targetDomain) && targetDomain !== "*") continue;
    } catch {
      continue;
    }

    // Normalize URL — strip query params for grouping
    let normalizedUrl: string;
    try {
      const u = new URL(req.url);
      normalizedUrl = `${u.origin}${u.pathname}`;
    } catch {
      normalizedUrl = req.url;
    }

    const key = `${req.method}::${normalizedUrl}`;
    const existing = map.get(key);

    if (existing) {
      existing.count++;
      existing.lastStatus = req.response?.status ?? existing.lastStatus;
    } else {
      map.set(key, {
        url: normalizedUrl,
        method: req.method,
        count: 1,
        lastStatus: req.response?.status ?? null,
        exampleHeaders: req.headers,
        exampleBody: req.body,
      });
    }
  }

  return [...map.values()].sort((a, b) => b.count - a.count);
}

function findCommonHeaders(requests: CapturedRequest[]): Record<string, string> {
  if (requests.length === 0) return {};

  const threshold = Math.max(1, Math.floor(requests.length * 0.7)); // in 70%+ of requests
  const counts = new Map<string, Map<string, number>>(); // header → value → count

  for (const req of requests) {
    for (const [k, v] of Object.entries(req.headers)) {
      if (!counts.has(k)) counts.set(k, new Map());
      const vc = counts.get(k)!;
      vc.set(v, (vc.get(v) ?? 0) + 1);
    }
  }

  const common: Record<string, string> = {};
  for (const [header, valueCounts] of counts) {
    for (const [value, count] of valueCounts) {
      if (count >= threshold) {
        common[header] = value;
        break;
      }
    }
  }

  // Remove boring/transport headers
  const boring = ["host", "content-length", "accept-encoding", "connection"];
  for (const key of boring) delete common[key];

  return common;
}
