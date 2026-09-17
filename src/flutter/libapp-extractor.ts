/**
 * Flutter libapp.so extractor
 *
 * Flutter compiles Dart to native code — jadx gives you nothing useful for
 * the app logic. But string literals (URLs, headers, endpoints, keys)
 * survive compilation and sit plaintext inside libapp.so.
 *
 * Pipeline:
 *   1. Detect APK / XAPK
 *   2. Extract libapp.so (arm64-v8a first, then other ABIs)
 *   3. Run `strings` on the binary
 *   4. Filter noise (Flutter stdlib, Dart core, Android framework)
 *   5. Categorize into a structured report
 *   6. Optionally run reFlutter for deeper snapshot reconstruction
 *
 * Covers the bulk of what you need from a non-obfuscated Flutter app.
 * For obfuscated apps, use dynamic capture (frida + mitmproxy) instead.
 */

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, statSync } from "node:fs";
import { writeFile, rm, readdir } from "node:fs/promises";
import { join, basename, extname } from "node:path";
import { tmpdir } from "node:os";
import { createLogger } from "../logger.js";

const log = createLogger("flutter-extractor");

// ── Types ────────────────────────────────────────────────────

export interface AuthConfig {
  apiKeys: string[];
  bearerTokenPatterns: string[];
  clientIds: string[];
  clientSecrets: string[];
  oauthEndpoints: string[];
}

export interface FlutterStringReport {
  apkPath: string;
  analyzedAt: string;
  isFlutter: boolean;
  isObfuscated: boolean;
  libappFound: boolean;
  libappSizeBytes: number;
  abi: string;

  /** API base URLs (full https:// URLs that look like API roots) */
  baseUrls: string[];
  /** Extracted endpoint paths (/api/v1/...) */
  endpoints: string[];
  /** All unique domains */
  domains: string[];
  /** Header name → value pairs seen in the binary */
  headers: Record<string, string>;
  /** User-Agent strings */
  userAgents: string[];
  /** App version strings */
  appVersions: string[];

  auth: AuthConfig;

  /** DataDome SDK key if detected */
  datadomeSdkKey: string | null;
  /** Other WAF/SDK keys */
  sdkKeys: Record<string, string>;

  /** Interesting strings that don't fit other categories */
  interesting: string[];

  stats: {
    totalStrings: number;
    afterFilter: number;
    categorized: number;
  };
}

export interface ExtractorOptions {
  /** Minimum string length for `strings`. Default: 8 */
  minLength?: number;
  /** Keep the working directory for inspection. Default: false */
  keepWorkDir?: boolean;
  /** Run reFlutter if available. Default: false (slow) */
  reFlutter?: boolean;
  /** Output directory for the report */
  outputDir?: string;
}

// ── Noise patterns (Flutter stdlib / Dart core / Android framework) ──

const NOISE_PREFIXES = [
  "dart.", "flutter.", "package:flutter", "package:dart",
  "package:material", "package:cupertino",
  "android.", "com.google.", "com.android.",
  "io.flutter.", "androidx.", "kotlin.",
  "java.", "javax.", "sun.", "org.json.",
];

const NOISE_EXACT = new Set([
  "true", "false", "null", "undefined", "NaN", "Infinity",
  "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS",
  "utf-8", "UTF-8", "application/json", "text/plain",
  "Content-Type", "Authorization", "Accept", "Cookie",
]);

const NOISE_CONTAINS = [
  "Expected", "Unexpected", "Exception", "Error:", "Warning:",
  "assert", "Stack trace", "RangeError", "TypeError",
  "Null check", "Cannot ", "Failed to", "Invalid ",
  "#0 ", "#1 ", "#2 ", // stack frame markers
  "<anonymous closure>", "closure", "_Closure",
];

// ── Core extraction ──────────────────────────────────────────

export async function analyzeFlutterApp(
  apkPath: string,
  opts: ExtractorOptions = {},
): Promise<FlutterStringReport> {
  const {
    minLength = 8,
    keepWorkDir = false,
    reFlutter: runReFlutter = false,
    outputDir = "./output/flutter",
  } = opts;

  const workDir = join(tmpdir(), `app2api-flutter-${Date.now()}`);
  mkdirSync(workDir, { recursive: true });
  mkdirSync(outputDir, { recursive: true });

  const report: FlutterStringReport = {
    apkPath,
    analyzedAt: new Date().toISOString(),
    isFlutter: false,
    isObfuscated: false,
    libappFound: false,
    libappSizeBytes: 0,
    abi: "",
    baseUrls: [],
    endpoints: [],
    domains: [],
    headers: {},
    userAgents: [],
    appVersions: [],
    auth: { apiKeys: [], bearerTokenPatterns: [], clientIds: [], clientSecrets: [], oauthEndpoints: [] },
    datadomeSdkKey: null,
    sdkKeys: {},
    interesting: [],
    stats: { totalStrings: 0, afterFilter: 0, categorized: 0 },
  };

  try {
    // ── 1. Extract APK/XAPK ──────────────────────────────────
    const apkFile = resolveApk(apkPath, workDir);
    if (!apkFile) {
      log.error(`Could not resolve APK from: ${apkPath}`);
      return report;
    }

    // ── 2. Find libapp.so ────────────────────────────────────
    const { soPath, abi } = extractLibapp(apkFile, workDir);

    if (!soPath) {
      log.warn("libapp.so not found — not a Flutter app or heavily split APK");
      return report;
    }

    report.isFlutter = true;
    report.libappFound = true;
    report.abi = abi;
    report.libappSizeBytes = statSync(soPath).size;

    log.info(`libapp.so found: ${abi} ${Math.round(report.libappSizeBytes / 1024 / 1024)}MB`);

    if (!checkLibFlutter(apkFile)) {
      log.warn("libflutter.so not found — may not be Flutter despite libapp.so");
    }

    // ── 3. Extract strings ───────────────────────────────────
    const rawStrings = extractStrings(soPath, minLength);
    report.stats.totalStrings = rawStrings.length;
    log.info(`Extracted ${rawStrings.length} strings`);

    if (rawStrings.length < 100) {
      log.warn("Very few strings — app may be obfuscated");
      report.isObfuscated = true;
    }

    // ── 4. Filter noise ──────────────────────────────────────
    const filtered = filterNoise(rawStrings);
    report.stats.afterFilter = filtered.length;
    log.info(`After noise filter: ${filtered.length} strings`);

    // ── 5. Categorize ────────────────────────────────────────
    categorize(filtered, report);
    report.stats.categorized =
      report.baseUrls.length +
      report.endpoints.length +
      Object.keys(report.headers).length +
      report.auth.apiKeys.length +
      report.userAgents.length;

    // ── 6. reFlutter (optional) ──────────────────────────────
    if (runReFlutter) {
      const rfResult = await tryReFlutter(apkPath, workDir);
      if (rfResult) {
        mergeReFlutterFindings(rfResult, report);
      }
    }

    // ── 7. Save report ───────────────────────────────────────
    const outFile = join(outputDir, `${basename(apkPath, extname(apkPath))}-flutter-analysis.json`);
    await writeFile(outFile, JSON.stringify(report, null, 2), "utf-8");
    log.info(`Report saved: ${outFile}`);

    logSummary(report);
  } finally {
    if (!keepWorkDir) {
      await rm(workDir, { recursive: true, force: true });
    } else {
      log.info(`Work dir kept: ${workDir}`);
    }
  }

  return report;
}

// ── APK/XAPK resolution ──────────────────────────────────────

function resolveApk(apkPath: string, workDir: string): string | null {
  const ext = extname(apkPath).toLowerCase();

  if (ext === ".apk") return apkPath;

  if (ext === ".xapk") {
    log.info("XAPK detected — extracting base.apk");
    spawnSync("unzip", ["-o", apkPath, "base.apk", "-d", workDir], { encoding: "utf-8" });
    const basePath = join(workDir, "base.apk");
    if (existsSync(basePath)) return basePath;

    // Some XAPKs name the base APK differently — list and find it
    const list = spawnSync("unzip", ["-l", apkPath], { encoding: "utf-8" }).stdout;
    const apkMatch = list.match(/(\S+\.apk)/m);
    if (apkMatch) {
      spawnSync("unzip", ["-o", apkPath, apkMatch[1], "-d", workDir], { encoding: "utf-8" });
      return join(workDir, apkMatch[1]);
    }
    return null;
  }

  if (ext === ".aab") {
    log.warn("AAB format — requires bundletool to extract. Supply an APK instead.");
    return null;
  }

  return apkPath; // assume APK
}

// ── libapp.so extraction ─────────────────────────────────────

const ABI_PREFERENCE = ["arm64-v8a", "x86_64", "armeabi-v7a", "x86"];

function extractLibapp(
  apkFile: string,
  workDir: string,
): { soPath: string | null; abi: string } {
  for (const abi of ABI_PREFERENCE) {
    const remotePath = `lib/${abi}/libapp.so`;
    spawnSync("unzip", ["-o", apkFile, remotePath, "-d", workDir], { encoding: "utf-8" });

    const extracted = join(workDir, remotePath);
    if (existsSync(extracted)) {
      return { soPath: extracted, abi };
    }
  }

  return { soPath: null, abi: "" };
}

function checkLibFlutter(apkFile: string): boolean {
  const listing = spawnSync("unzip", ["-l", apkFile], { encoding: "utf-8" }).stdout;
  return ABI_PREFERENCE.some((abi) => listing.includes(`lib/${abi}/libflutter.so`));
}

// ── String extraction ────────────────────────────────────────

function extractStrings(soPath: string, minLength: number): string[] {
  // -n: minimum length, -e s: 7-bit encoding
  const result = spawnSync("strings", ["-n", String(minLength), "-e", "s", soPath], {
    encoding: "utf-8",
    maxBuffer: 100 * 1024 * 1024,
  });

  if (result.error) {
    log.error(`strings command failed: ${result.error.message}`);
    return fallbackStringExtract(soPath, minLength);
  }

  return result.stdout
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length >= minLength);
}

function fallbackStringExtract(soPath: string, minLength: number): string[] {
  log.warn("Using fallback string extractor (grep on raw bytes)");
  const result = spawnSync("grep", ["-oaP", `[\\x20-\\x7E]{${minLength},}`, soPath], {
    encoding: "utf-8",
    maxBuffer: 100 * 1024 * 1024,
  });
  return (result.stdout ?? "").split("\n").filter((s) => s.length >= minLength);
}

// ── Noise filtering ───────────────────────────────────────────

export function filterNoise(strings: string[]): string[] {
  return strings.filter((s) => {
    if (NOISE_EXACT.has(s)) return false;
    if (NOISE_PREFIXES.some((p) => s.startsWith(p))) return false;
    if (NOISE_CONTAINS.some((p) => s.includes(p))) return false;

    // Pure hex strings are likely addresses
    if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return false;

    // Repeated characters
    if (/^(.)\1{5,}$/.test(s)) return false;

    // Compiler artifact paths
    if (s.startsWith("/b/") || s.startsWith("/tmp/") || s.includes("flutter/packages")) return false;

    return true;
  });
}

// ── Categorization ────────────────────────────────────────────

const RE = {
  url:          /^https?:\/\/[^\s"'<>]+$/,
  endpoint:     /^\/[a-zA-Z0-9_\-/.]+$/,
  apiPath:      /\/(api|v\d|rest|graphql|search|listings?|classifieds?|auth|oauth|token)/i,
  domain:       /^([a-z0-9-]+\.)+[a-z]{2,}$/i,
  headerName:   /^[A-Z][a-zA-Z-]+-[A-Za-z-]+$|^X-[A-Za-z-]+$/,
  userAgent:    /^(Mozilla|Dalvik|Dart|okhttp|CFNetwork|python|curl)/i,
  version:      /^\d+\.\d+\.\d+(\.\d+)?$/,
  clientId:     /(client.?id|app.?id|consumer.?key)/i,
  clientSecret: /(client.?secret|consumer.?secret|app.?secret)/i,
  oauth:        /\/(oauth|token|authorize|access_token)/i,
  sdkKey:       /^[A-Za-z0-9_-]{32,64}$/,
  bearer:       /^Bearer\s/i,
  jwt:          /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
};

const NOISE_DOMAINS = new Set([
  "flutter.dev", "dart.dev", "pub.dev", "google.com", "googleapis.com",
  "gstatic.com", "firebase.com", "crashlytics.com", "sentry.io",
  "facebook.com", "twitter.com", "instagram.com", "amazonaws.com",
  "cloudfront.net", "fastly.net",
]);

export function categorize(strings: string[], report: FlutterStringReport): void {
  const urlsSeen = new Set<string>();
  const endpointsSeen = new Set<string>();
  const domainsSeen = new Set<string>();
  let prevString = "";

  for (const s of strings) {
    // URLs
    if (RE.url.test(s) && s.length < 300) {
      try {
        const u = new URL(s);
        const domain = u.hostname;

        if (!NOISE_DOMAINS.has(domain) && !urlsSeen.has(s)) {
          urlsSeen.add(s);
          // Only a base URL if it looks like an API root
          if (RE.apiPath.test(u.pathname) || u.pathname.length < 4) {
            report.baseUrls.push(s);
          }
          domainsSeen.add(domain);
        }
      } catch { /* invalid URL */ }
    }

    // Endpoint paths
    else if (RE.endpoint.test(s) && RE.apiPath.test(s) && s.length > 3 && !endpointsSeen.has(s)) {
      endpointsSeen.add(s);
      report.endpoints.push(s);
    }

    // User agents
    else if (RE.userAgent.test(s) && s.length > 10) {
      report.userAgents.push(s);
    }

    // Version strings
    else if (RE.version.test(s)) {
      report.appVersions.push(s);
    }

    // JWTs
    else if (RE.jwt.test(s)) {
      report.auth.bearerTokenPatterns.push(s);
    }

    // DataDome SDK key (32–64 char token right after a "datadome" context string)
    else if (prevString.toLowerCase().includes("datadome") && RE.sdkKey.test(s)) {
      report.datadomeSdkKey = s;
    }

    // Header name, then value via prevString correlation
    else if (RE.headerName.test(s) && s.length < 60) {
      report.headers[s] = ""; // placeholder, filled by the next string
    } else if (prevString in report.headers && report.headers[prevString] === "") {
      report.headers[prevString] = s;
    }

    // OAuth endpoints
    else if (RE.url.test(s) && RE.oauth.test(s)) {
      report.auth.oauthEndpoints.push(s);
    }

    // Interesting catch-all
    else if (
      s.length > 10 && s.length < 200 &&
      !s.includes("\n") &&
      /[a-zA-Z]/.test(s) &&
      !/^[A-Z_]+$/.test(s)
    ) {
      report.interesting.push(s);
    }

    prevString = s;
  }

  // Drop header names that never got a value
  for (const [k, v] of Object.entries(report.headers)) {
    if (!v) delete report.headers[k];
  }

  report.baseUrls = [...new Set(report.baseUrls)];
  report.endpoints = [...new Set(report.endpoints)];
  report.domains = [...domainsSeen];
  report.userAgents = [...new Set(report.userAgents)];
  report.appVersions = [...new Set(report.appVersions)].slice(0, 10);
  report.interesting = [...new Set(report.interesting)].slice(0, 100);
}

// ── reFlutter integration ─────────────────────────────────────

async function tryReFlutter(apkPath: string, workDir: string): Promise<string | null> {
  const check = spawnSync("reFlutter", ["--version"], { encoding: "utf-8" });
  if (check.error) {
    log.warn("reFlutter not installed (pip install reflutter). Skipping.");
    return null;
  }

  log.info("Running reFlutter (this patches the APK and takes ~30s)...");
  const result = spawnSync("reFlutter", [apkPath], {
    encoding: "utf-8",
    cwd: workDir,
    timeout: 120_000,
  });

  if (result.status !== 0) {
    log.warn(`reFlutter failed: ${result.stderr}`);
    return null;
  }

  const resultsDir = join(workDir, "reFlutter_results");
  if (!existsSync(resultsDir)) return null;

  const files = await readdir(resultsDir);
  const dumpFile = files.find((f) => f.endsWith(".dart") || f.endsWith(".txt"));
  if (!dumpFile) return null;

  log.info(`reFlutter produced: ${dumpFile}`);
  return join(resultsDir, dumpFile);
}

function mergeReFlutterFindings(dumpPath: string, report: FlutterStringReport): void {
  try {
    const content = readFileSync(dumpPath, "utf-8");
    const lines = content.split("\n");

    for (const line of lines) {
      const urlMatch = line.match(/https?:\/\/[^\s"']+/);
      if (urlMatch && !report.baseUrls.includes(urlMatch[0])) {
        report.baseUrls.push(urlMatch[0]);
      }

      const endpointMatch = line.match(/\/[a-zA-Z0-9_\-/]+/);
      if (endpointMatch && RE.apiPath.test(endpointMatch[0])) {
        if (!report.endpoints.includes(endpointMatch[0])) {
          report.endpoints.push(endpointMatch[0]);
        }
      }
    }

    log.info(`reFlutter findings merged: ${report.baseUrls.length} URLs total`);
  } catch (e) {
    log.warn(`Failed to parse reFlutter output: ${(e as Error).message}`);
  }
}

// ── Logging ───────────────────────────────────────────────────

function logSummary(r: FlutterStringReport): void {
  log.info("─".repeat(50));
  log.info(`Flutter: ${r.isFlutter} | Obfuscated: ${r.isObfuscated} | ABI: ${r.abi}`);
  log.info(`Strings: ${r.stats.totalStrings} total → ${r.stats.afterFilter} after filter`);
  log.info(`Found: ${r.baseUrls.length} URLs | ${r.endpoints.length} endpoints | ${r.domains.length} domains`);
  log.info(`Headers: ${Object.keys(r.headers).length} | UserAgents: ${r.userAgents.length}`);
  if (r.datadomeSdkKey) log.info(`DataDome SDK key: ${r.datadomeSdkKey}`);
  if (r.auth.oauthEndpoints.length) log.info(`OAuth endpoints: ${r.auth.oauthEndpoints.join(", ")}`);
  log.info("─".repeat(50));
}
