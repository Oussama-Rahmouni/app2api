/**
 * Pattern extractor — scans decompiled APK source for URLs, endpoints,
 * OAuth material, API keys, and custom headers. Works on any directory of
 * decompiled output (jadx, apktool, or hand-pulled smali) with zero
 * external tools.
 */

import { readdir, readFile } from "node:fs/promises";
import { join, basename } from "node:path";
import type { ApkReport, OAuthFlow } from "./types.js";
import { createLogger } from "./logger.js";

const log = createLogger("apk-analyzer");

export const NOISE_DOMAINS = new Set([
  "schemas.android.com",
  "www.w3.org",
  "ns.adobe.com",
  "xml.org",
  "googleapis.com",
  "google.com",
  "gstatic.com",
  "firebase.io",
  "firebaseio.com",
  "firebase.google.com",
  "crashlytics.com",
  "fabric.io",
  "app-measurement.com",
  "googleadservices.com",
  "googlesyndication.com",
  "doubleclick.net",
  "google-analytics.com",
  "googletagmanager.com",
  "play.google.com",
  "android.com",
  "localhost",
]);

export const PATTERNS = {
  urls: /https?:\/\/[a-zA-Z0-9][-a-zA-Z0-9.]+\.[a-zA-Z]{2,}[/a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=-]*/g,
  oauth: /(?:client_id|client_secret|grant_type|token_endpoint|oauth|\/oauth\/|\/token)/gi,
  apiKeys: /(?:api[_-]?key|x-api-key|authorization|apikey)\s*[:=]\s*["']?([^"'\s,;]+)/gi,
  endpoints: /["']\/(?:api|v[0-9]|rest|graphql|mobile)[/a-zA-Z0-9._-]*["']/g,
  headers: /["'](?:User-Agent|X-App-Version|X-Client-Id|X-Api-Key|X-Device-Id|X-Platform|X-App-Build)['"]\s*[:=,]/gi,
  clientId: /(?:client[_-]?id)\s*[:=]\s*["']([^"']+)["']/gi,
  clientSecret: /(?:client[_-]?secret)\s*[:=]\s*["']([^"']+)["']/gi,
  tokenUrl: /(?:token[_-]?url|token[_-]?endpoint|oauth.*?url)\s*[:=]\s*["']([^"']+)["']/gi,
  grantType: /grant[_-]?type\s*[:=]\s*["']([^"']+)["']/gi,
};

export function isNoise(url: string): boolean {
  try {
    const hostname = new URL(url).hostname;
    return NOISE_DOMAINS.has(hostname) ||
      [...NOISE_DOMAINS].some((d) => hostname.endsWith("." + d));
  } catch {
    return true;
  }
}

function dedup(arr: string[]): string[] {
  return [...new Set(arr)].sort();
}

const SCANNED_EXTENSIONS = [".java", ".kt", ".xml", ".json", ".smali"];

async function walkSources(dir: string, onFile: (content: string, path: string) => void): Promise<void> {
  async function walk(d: string) {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) {
        await walk(full);
      } else if (SCANNED_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) {
        try {
          onFile(await readFile(full, "utf-8"), full);
        } catch {
          // skip unreadable files
        }
      }
    }
  }
  await walk(dir);
}

async function grepRecursive(dir: string, pattern: RegExp): Promise<string[]> {
  const results: string[] = [];
  await walkSources(dir, (content) => {
    const matches = content.match(pattern);
    if (matches) results.push(...matches);
  });
  return results;
}

async function grepWithCapture(dir: string, pattern: RegExp): Promise<string[]> {
  const results: string[] = [];
  await walkSources(dir, (content) => {
    const re = new RegExp(pattern.source, pattern.flags);
    let match;
    while ((match = re.exec(content)) !== null) {
      if (match[1]) results.push(match[1]);
    }
  });
  return results;
}

async function findFile(dir: string, filename: string): Promise<boolean> {
  let found = false;
  async function walk(d: string): Promise<void> {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      if (found) return;
      if (entry.name === filename) {
        found = true;
        return;
      }
      if (entry.isDirectory()) await walk(join(d, entry.name));
    }
  }
  await walk(dir);
  return found;
}

/**
 * Analyze an already-decompiled APK directory (e.g. jadx output).
 * Decompilation is the pipeline's job — this function never shells out.
 */
export async function analyzeApk(decompiledDir: string, appName?: string): Promise<ApkReport> {
  const name = appName ?? basename(decompiledDir.replace(/\/+$/, ""));
  log.info(`Analyzing decompiled sources at: ${decompiledDir}`);

  const isFlutter = await findFile(decompiledDir, "libflutter.so");
  if (isFlutter) {
    log.warn("Flutter markers detected — decompiled Java may not contain primary app logic");
  }

  log.info("Scanning for URL/auth/key patterns...");
  const [rawUrls, rawOauth, rawApiKeys, rawEndpoints, rawHeaders, clientIds, secrets, tokenUrls, grantTypes] =
    await Promise.all([
      grepRecursive(decompiledDir, PATTERNS.urls),
      grepRecursive(decompiledDir, PATTERNS.oauth),
      grepWithCapture(decompiledDir, PATTERNS.apiKeys),
      grepRecursive(decompiledDir, PATTERNS.endpoints),
      grepRecursive(decompiledDir, PATTERNS.headers),
      grepWithCapture(decompiledDir, PATTERNS.clientId),
      grepWithCapture(decompiledDir, PATTERNS.clientSecret),
      grepWithCapture(decompiledDir, PATTERNS.tokenUrl),
      grepWithCapture(decompiledDir, PATTERNS.grantType),
    ]);

  // Filter noise
  const urls = dedup(rawUrls.filter((u) => !isNoise(u)));
  const baseUrls = dedup(
    urls
      .map((u) => {
        try {
          const parsed = new URL(u);
          return `${parsed.protocol}//${parsed.hostname}`;
        } catch {
          return "";
        }
      })
      .filter(Boolean),
  );
  const endpoints = dedup(rawEndpoints.map((e) => e.replace(/["']/g, "")));

  // Build OAuth flows
  const oauthFlows: OAuthFlow[] = [];
  for (const tu of dedup(tokenUrls)) {
    oauthFlows.push({
      tokenUrl: tu,
      grantType: grantTypes[0] ?? "password",
      clientId: clientIds[0],
      clientSecret: secrets[0],
    });
  }
  if (oauthFlows.length === 0 && clientIds.length > 0) {
    oauthFlows.push({
      tokenUrl: "unknown",
      grantType: grantTypes[0] ?? "unknown",
      clientId: clientIds[0],
      clientSecret: secrets[0],
    });
  }

  // Package name from the manifest
  let packageName = name;
  try {
    const manifest = await readFile(join(decompiledDir, "AndroidManifest.xml"), "utf-8");
    const pkgMatch = manifest.match(/package="([^"]+)"/);
    if (pkgMatch) packageName = pkgMatch[1];
  } catch {
    // no manifest available
  }

  const report: ApkReport = {
    appName: name,
    packageName,
    analyzedAt: new Date().toISOString(),
    isFlutter,
    baseUrls,
    endpoints,
    authConfig: {
      clientIds: dedup(clientIds),
      secrets: dedup(secrets),
      apiKeys: dedup(rawApiKeys),
      oauthFlows,
    },
    headers: {},
    rawFindings: {
      urls,
      authTokens: dedup(rawOauth),
      apiEndpoints: endpoints,
      customHeaders: dedup(rawHeaders),
    },
  };

  log.info(`Base URLs: ${report.baseUrls.length}, endpoints: ${report.endpoints.length}, ` +
    `OAuth flows: ${report.authConfig.oauthFlows.length}, API keys: ${report.authConfig.apiKeys.length}`);

  return report;
}
