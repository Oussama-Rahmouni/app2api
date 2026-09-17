/**
 * Intel Extractor — everything in a decompiled APK that isn't the API
 * surface itself:
 * - Third-party SDK keys (Google, Firebase, Facebook, Sentry, Stripe, analytics, CMP)
 * - Infrastructure intel (URLs, AWS/GCP resources, staging/admin/CMS/CDN endpoints)
 * - Security posture (network security config, manifest flags, WebView issues, raw SQL)
 * - Data models & storage (SharedPreferences keys, Room/SQLite tables, @SerializedName models)
 * - Build info (BuildConfig fields, developer emails)
 * - Deep link schemes
 * - Feature flags & remote config
 */

import { readdir, readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { createLogger } from "./logger.js";

const log = createLogger("intel-extractor");

// ─── Types ───────────────────────────────────────────────────────

export interface IntelReport {
  appName: string;
  packageName: string;
  analyzedAt: string;

  sdkKeys: {
    google: { mapsApiKey: string | null; appId: string | null; clientId: string | null; crashReportingKey: string | null };
    firebase: { databaseUrl: string | null; storageBucket: string | null; projectId: string | null; senderId: string | null };
    facebook: { appId: string | null; clientToken: string | null };
    sentry: { dsn: string | null };
    stripe: { publishableKey: string | null; secretKey: string | null };
    analytics: Array<{ provider: string; key: string }>;
    other: Array<{ name: string; value: string; source: string }>;
  };

  infrastructure: {
    allUrls: Array<{ url: string; category: string; source: string }>;
    awsResources: string[];
    gcpResources: string[];
    stagingUrls: string[];
    adminUrls: string[];
    cmsEndpoints: string[];
    cdnDomains: string[];
  };

  security: {
    networkConfig: {
      cleartextAllowed: boolean;
      certPinning: boolean;
      pinnedDomains: string[];
      debugOverrides: boolean;
      trustAnchors: string[];
    };
    manifest: {
      allowBackup: boolean;
      debuggable: boolean;
      cleartextTraffic: boolean;
      exportedComponents: Array<{ name: string; type: string; intentFilters: string[] }>;
      permissions: string[];
      deepLinks: Array<{ scheme: string; host: string; path: string }>;
    };
    webviewIssues: Array<{ file: string; issue: string }>;
    sqlInjection: Array<{ file: string; query: string }>;
  };

  storage: {
    sharedPrefsKeys: Array<{ key: string; type: string; file: string }>;
    databases: Array<{ name: string; version: number | null; tables: string[] }>;
    allModels: Array<{ name: string; file: string; fields: Array<{ serializedName: string; type: string; name: string }> }>;
  };

  buildInfo: {
    applicationId: string | null;
    versionName: string | null;
    versionCode: string | null;
    buildType: string | null;
    isDebug: boolean;
    customFields: Record<string, string>;
    targetSdk: string | null;
    minSdk: string | null;
  };

  deepLinks: Array<{ scheme: string; host: string; pathPattern: string | null; activity: string }>;

  featureFlags: Array<{ name: string; defaultValue: string | null; source: string }>;
}

// ─── File Utilities ──────────────────────────────────────────────

async function readFileSafe(path: string): Promise<string> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return "";
  }
}

/**
 * Walk ALL source files including SDK dirs (unlike the deep analyzer which
 * skips them — SDK configs live inside com/facebook, com/google/firebase...).
 */
async function findAllJavaFiles(dir: string): Promise<string[]> {
  const files: string[] = [];

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
        // Only skip truly massive noise dirs that never contain useful intel
        if (
          entry.name === "android" ||
          entry.name === "androidx" ||
          entry.name === "kotlin" ||
          entry.name === "kotlinx"
        ) {
          continue;
        }
        await walk(full);
      } else if (entry.name.endsWith(".java") || entry.name.endsWith(".kt")) {
        files.push(full);
      }
    }
  }

  await walk(dir);
  return files;
}

async function findResourceFiles(dir: string, extensions: string[]): Promise<string[]> {
  const files: string[] = [];

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
      } else if (extensions.some((ext) => entry.name.endsWith(ext))) {
        files.push(full);
      }
    }
  }

  await walk(dir);
  return files;
}

// ─── 1. SDK Keys ─────────────────────────────────────────────────

async function extractSdkKeys(
  stringsXml: string,
  fileContents: Map<string, string>,
): Promise<IntelReport["sdkKeys"]> {
  const result: IntelReport["sdkKeys"] = {
    google: { mapsApiKey: null, appId: null, clientId: null, crashReportingKey: null },
    firebase: { databaseUrl: null, storageBucket: null, projectId: null, senderId: null },
    facebook: { appId: null, clientToken: null },
    sentry: { dsn: null },
    stripe: { publishableKey: null, secretKey: null },
    analytics: [],
    other: [],
  };

  // Parse strings.xml for known SDK keys
  const stringEntries = new Map<string, string>();
  const stringMatches = Array.from(stringsXml.matchAll(/<string name="([^"]+)"[^>]*>([^<]*)<\/string>/g));
  for (const m of stringMatches) {
    stringEntries.set(m[1], m[2]);
  }

  result.google.mapsApiKey = stringEntries.get("google_api_key") ?? null;
  result.google.appId = stringEntries.get("google_app_id") ?? null;
  result.google.crashReportingKey = stringEntries.get("google_crash_reporting_api_key") ?? null;

  result.firebase.databaseUrl = stringEntries.get("firebase_database_url") ?? null;
  result.firebase.storageBucket = stringEntries.get("google_storage_bucket") ?? null;
  result.firebase.projectId = stringEntries.get("project_id") ?? null;
  result.firebase.senderId = stringEntries.get("gcm_defaultSenderId") ?? null;

  result.facebook.appId = stringEntries.get("facebook_app_id") ?? null;
  result.facebook.clientToken = stringEntries.get("facebook_client_token") ?? null;

  // Consent management platforms
  const didomiKey = stringEntries.get("didomi_api_key");
  if (didomiKey) {
    result.other.push({ name: "didomi_api_key", value: didomiKey, source: "strings.xml" });
  }

  // Scan source files for additional keys
  const seenKeys = new Set<string>();

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;

    // Google API keys in source (AIza pattern)
    const googleKeyMatches = Array.from(content.matchAll(/AIza[0-9A-Za-z_-]{35}/g));
    for (const m of googleKeyMatches) {
      if (!seenKeys.has(m[0])) {
        seenKeys.add(m[0]);
        if (!result.google.mapsApiKey) {
          result.google.mapsApiKey = m[0];
        } else if (m[0] !== result.google.mapsApiKey && m[0] !== result.google.crashReportingKey) {
          result.other.push({ name: "google_api_key", value: m[0], source: shortFile });
        }
      }
    }

    // Sentry DSN
    const sentryMatch = content.match(/https:\/\/[a-f0-9]+@[a-z]+\.ingest\.sentry\.io\/[0-9]+/);
    if (sentryMatch && !result.sentry.dsn) {
      result.sentry.dsn = sentryMatch[0];
    }

    // Stripe keys
    const stripePkMatch = content.match(/pk_(?:live|test)_[A-Za-z0-9]+/);
    if (stripePkMatch && !result.stripe.publishableKey) {
      result.stripe.publishableKey = stripePkMatch[0];
    }
    const stripeSkMatch = content.match(/sk_(?:live|test)_[A-Za-z0-9]+/);
    if (stripeSkMatch && !result.stripe.secretKey) {
      result.stripe.secretKey = stripeSkMatch[0];
      log.info(`Stripe secret key found in ${shortFile}`);
    }

    // Generic API keys in source code
    const genericKeyMatches = Array.from(
      content.matchAll(/(?:private|public|protected|static|final|\s)+\s+(?:String|string)\s+(\w*(?:api[_]?key|apikey|API_KEY|secret[_]?key|SECRET)\w*)\s*=\s*"([^"]{8,})"/gi),
    );
    for (const m of genericKeyMatches) {
      const fullKey = `${m[1]}:${m[2]}`;
      if (!seenKeys.has(fullKey)) {
        seenKeys.add(fullKey);
        result.other.push({ name: m[1], value: m[2], source: shortFile });
        log.info(`Generic key: ${m[1]} in ${shortFile}`);
      }
    }

    // Analytics SDKs
    const amplitudeMatch = content.match(/Amplitude\.getInstance\(\)\.init(?:ialize)?\(\s*(?:this\s*,\s*)?"([^"]+)"/);
    if (amplitudeMatch) result.analytics.push({ provider: "amplitude", key: amplitudeMatch[1] });

    const mixpanelMatch = content.match(/MixpanelAPI\.getInstance\([^,]*,\s*"([^"]+)"/);
    if (mixpanelMatch) result.analytics.push({ provider: "mixpanel", key: mixpanelMatch[1] });

    const segmentMatch = content.match(/Analytics\.with\([^)]*\)[\s\S]*?writeKey\(\s*"([^"]+)"/);
    if (segmentMatch) {
      result.analytics.push({ provider: "segment", key: segmentMatch[1] });
    } else {
      const segmentConstMatch = content.match(/SEGMENT_WRITE_KEY\s*=\s*"([^"]+)"/);
      if (segmentConstMatch) result.analytics.push({ provider: "segment", key: segmentConstMatch[1] });
    }

    const adjustMatch = content.match(/AdjustConfig\(\s*"([^"]+)"/);
    if (adjustMatch) result.analytics.push({ provider: "adjust", key: adjustMatch[1] });

    const appsflyerMatch = content.match(/AppsFlyerLib\.getInstance\(\)\.init\(\s*"([^"]+)"/);
    if (appsflyerMatch) result.analytics.push({ provider: "appsflyer", key: appsflyerMatch[1] });
  }

  // Remaining key-like entries in strings.xml
  for (const [name, value] of Array.from(stringEntries.entries())) {
    if (
      /(?:api_key|apikey|app_key|app_token|write_key|dev_key|client_key)/i.test(name) &&
      !name.startsWith("google_") &&
      !name.startsWith("firebase_") &&
      !name.startsWith("facebook_") &&
      !name.startsWith("didomi_") &&
      !name.startsWith("abc_") &&
      value.length >= 8
    ) {
      const fullKey = `str:${name}:${value}`;
      if (!seenKeys.has(fullKey)) {
        seenKeys.add(fullKey);
        result.other.push({ name, value, source: "strings.xml" });
      }
    }
  }

  return result;
}

// ─── 2. Infrastructure Intel ─────────────────────────────────────

export function categorizeUrl(url: string): string {
  const lower = url.toLowerCase();

  if (/\.(png|jpg|jpeg|gif|svg|webp|ico|bmp|woff|woff2|ttf|eot|otf|css|js)$/i.test(lower)) return "static-asset";
  if (/cloudfront\.net|cdn\.|akamaized\.net|fastly\.net|cloudinary\.com|imgix\.net/i.test(lower)) return "cdn";
  if (/google-analytics\.com|analytics\.|amplitude\.com|mixpanel\.com|segment\.io|adjust\.com|appsflyer\.com|branch\.io|app-measurement\.com/i.test(lower)) return "analytics";
  if (/googleapis\.com|firebaseio\.com|firebase|fcm|crashlytics/i.test(lower)) return "google-service";
  if (/sentry\.io|bugsnag\.com|crashlytics/i.test(lower)) return "error-tracking";
  if (/facebook\.com|fb\.com|fbcdn\.net/i.test(lower)) return "facebook";
  if (/didomi\.io/i.test(lower)) return "consent-management";
  if (/staging\.|dev\.|qa\.|test\.|sandbox\.|internal\./i.test(lower)) return "staging/dev";
  if (/admin\.|backoffice\.|cms\.|dashboard\./i.test(lower)) return "admin";
  if (/wp-json|wordpress|wp-content|wp-admin/i.test(lower)) return "cms-wordpress";
  if (/\/api\/|\/v[0-9]+\//i.test(lower)) return "api";
  if (/play\.google\.com|apple\.com\/app|apps\.apple\.com/i.test(lower)) return "app-store";
  if (/schemas\.android\.com|w3\.org|xml\.org|schema\.org/i.test(lower)) return "schema/spec";

  return "other";
}

async function extractInfrastructure(
  fileContents: Map<string, string>,
  stringsXml: string,
  resourceFiles: string[],
): Promise<IntelReport["infrastructure"]> {
  const result: IntelReport["infrastructure"] = {
    allUrls: [],
    awsResources: [],
    gcpResources: [],
    stagingUrls: [],
    adminUrls: [],
    cmsEndpoints: [],
    cdnDomains: [],
  };

  const seenUrls = new Set<string>();
  const urlPattern = /https?:\/\/[a-zA-Z0-9.-]+\.[a-z]{2,}[/a-zA-Z0-9._~:/?#[\]@!$&'()*+,;=%-]*/g;

  const noisePatterns = [
    /schemas\.android\.com/,
    /www\.w3\.org/,
    /xmlns\./,
    /ns\.adobe\.com/,
    /apache\.org/,
    /xml\.org/,
    /schema\.org\/type/,
    /example\.com/,
    /localhost/,
  ];

  function addUrl(url: string, source: string) {
    // Clean trailing punctuation
    url = url.replace(/[.,;:!?)}\]'"]+$/, "");
    if (url.length < 10) return;
    if (seenUrls.has(url)) return;
    if (noisePatterns.some((p) => p.test(url))) return;

    seenUrls.add(url);
    const category = categorizeUrl(url);

    result.allUrls.push({ url, category, source });

    if (category === "staging/dev") result.stagingUrls.push(url);
    if (category === "admin") result.adminUrls.push(url);
    if (category === "cms-wordpress") result.cmsEndpoints.push(url);

    if (category === "cdn") {
      try {
        const domain = new URL(url).hostname;
        if (!result.cdnDomains.includes(domain)) result.cdnDomains.push(domain);
      } catch { /* invalid URL */ }
    }

    if (/amazonaws\.com|s3:\/\/|cognito|lambda\..*\.amazonaws/i.test(url)) {
      if (!result.awsResources.includes(url)) result.awsResources.push(url);
    }

    if (/googleapis\.com|\.appspot\.com|cloudfunctions\.net|run\.app/i.test(url)) {
      if (!result.gcpResources.includes(url)) result.gcpResources.push(url);
    }
  }

  const stringsUrlMatches = Array.from(stringsXml.matchAll(urlPattern));
  for (const m of stringsUrlMatches) {
    addUrl(m[0], "strings.xml");
  }

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;
    const matches = Array.from(content.matchAll(urlPattern));
    for (const m of matches) {
      addUrl(m[0], shortFile);
    }

    const s3Matches = Array.from(content.matchAll(/s3:\/\/[a-zA-Z0-9._-]+/g));
    for (const m of s3Matches) {
      if (!result.awsResources.includes(m[0])) result.awsResources.push(m[0]);
    }
  }

  for (const resFile of resourceFiles) {
    const content = await readFileSafe(resFile);
    if (!content) continue;
    const shortFile = resFile.split("/").slice(-3).join("/");
    const matches = Array.from(content.matchAll(urlPattern));
    for (const m of matches) {
      addUrl(m[0], shortFile);
    }
  }

  // appspot storage buckets in strings.xml count as GCP resources
  const stringsEntries = Array.from(stringsXml.matchAll(/<string name="([^"]+)"[^>]*>([^<]*)<\/string>/g));
  for (const m of stringsEntries) {
    const value = m[2];
    if (/\.appspot\.com$/i.test(value) && !result.gcpResources.includes(value)) {
      result.gcpResources.push(value);
    }
  }

  log.info(`Found ${result.allUrls.length} unique URLs ` +
    `(staging: ${result.stagingUrls.length}, admin: ${result.adminUrls.length}, ` +
    `cdn: ${result.cdnDomains.length}, aws: ${result.awsResources.length}, gcp: ${result.gcpResources.length})`);

  return result;
}

// ─── 3. Security Analysis ────────────────────────────────────────

async function extractNetworkSecurityConfig(outputDir: string): Promise<IntelReport["security"]["networkConfig"]> {
  const result: IntelReport["security"]["networkConfig"] = {
    cleartextAllowed: false,
    certPinning: false,
    pinnedDomains: [],
    debugOverrides: false,
    trustAnchors: [],
  };

  const candidates = [
    join(outputDir, "resources", "res", "xml", "network_security_config.xml"),
    join(outputDir, "res", "xml", "network_security_config.xml"),
  ];

  try {
    const resEntries = await readdir(join(outputDir, "resources"), { withFileTypes: true });
    for (const entry of resEntries) {
      if (entry.isDirectory()) {
        candidates.push(join(outputDir, "resources", entry.name, "res", "xml", "network_security_config.xml"));
      }
    }
  } catch { /* ignore */ }

  for (const path of candidates) {
    const content = await readFileSafe(path);
    if (!content) continue;

    log.info(`Found network_security_config at: ${path}`);

    if (/cleartextTrafficPermitted\s*=\s*"true"/i.test(content)) {
      result.cleartextAllowed = true;
    }

    if (/<pin-set/i.test(content)) {
      result.certPinning = true;
      const domainMatches = Array.from(content.matchAll(/domain\s+includeSubdomains\s*=\s*"[^"]*"\s*>([^<]+)/g));
      for (const m of domainMatches) {
        result.pinnedDomains.push(m[1].trim());
      }
    }

    if (/<debug-overrides/i.test(content)) {
      result.debugOverrides = true;
    }

    const trustMatches = Array.from(content.matchAll(/<certificates\s+src="([^"]+)"/g));
    for (const m of trustMatches) {
      result.trustAnchors.push(m[1]);
    }
  }

  return result;
}

async function extractManifestSecurity(outputDir: string): Promise<{
  manifest: IntelReport["security"]["manifest"];
  deepLinks: IntelReport["deepLinks"];
  buildInfo: Partial<IntelReport["buildInfo"]>;
  packageName: string;
}> {
  const manifest: IntelReport["security"]["manifest"] = {
    allowBackup: false,
    debuggable: false,
    cleartextTraffic: false,
    exportedComponents: [],
    permissions: [],
    deepLinks: [],
  };

  const deepLinks: IntelReport["deepLinks"] = [];
  const buildInfo: Partial<IntelReport["buildInfo"]> = {};
  let packageName = "unknown";

  const candidates = [join(outputDir, "AndroidManifest.xml")];
  try {
    const resEntries = await readdir(join(outputDir, "resources"), { withFileTypes: true });
    for (const entry of resEntries) {
      if (entry.isDirectory()) {
        candidates.push(join(outputDir, "resources", entry.name, "AndroidManifest.xml"));
      }
    }
  } catch { /* ignore */ }

  let manifestContent = "";
  for (const path of candidates) {
    const content = await readFileSafe(path);
    if (content && content.includes("<manifest")) {
      manifestContent = content;
      break;
    }
  }

  if (!manifestContent) {
    log.warn("AndroidManifest.xml not found");
    return { manifest, deepLinks, buildInfo, packageName };
  }

  const pkgMatch = manifestContent.match(/package="([^"]+)"/);
  if (pkgMatch) packageName = pkgMatch[1];

  const versionCodeMatch = manifestContent.match(/android:versionCode="([^"]+)"/);
  const versionNameMatch = manifestContent.match(/android:versionName="([^"]+)"/);
  const minSdkMatch = manifestContent.match(/android:minSdkVersion="([^"]+)"/);
  const targetSdkMatch = manifestContent.match(/android:targetSdkVersion="([^"]+)"/);
  if (versionCodeMatch) buildInfo.versionCode = versionCodeMatch[1];
  if (versionNameMatch) buildInfo.versionName = versionNameMatch[1];
  if (minSdkMatch) buildInfo.minSdk = minSdkMatch[1];
  if (targetSdkMatch) buildInfo.targetSdk = targetSdkMatch[1];

  manifest.allowBackup = /android:allowBackup="true"/i.test(manifestContent);
  manifest.debuggable = /android:debuggable="true"/i.test(manifestContent);
  manifest.cleartextTraffic = /android:usesCleartextTraffic="true"/i.test(manifestContent);

  if (manifest.debuggable) log.info("android:debuggable=true (debug build!)");
  if (manifest.cleartextTraffic) log.info("android:usesCleartextTraffic=true (HTTP allowed)");

  const permMatches = Array.from(manifestContent.matchAll(/uses-permission\s+android:name="([^"]+)"/g));
  for (const m of permMatches) {
    manifest.permissions.push(m[1]);
  }

  // Exported components
  const componentPatterns: Array<{ tag: string; type: string }> = [
    { tag: "activity", type: "activity" },
    { tag: "service", type: "service" },
    { tag: "receiver", type: "receiver" },
    { tag: "provider", type: "provider" },
  ];

  for (const { tag, type } of componentPatterns) {
    // Simple block matching to avoid catastrophic backtracking
    const tagRegex = new RegExp(`<${tag}[\\s\\S]*?(?:\\/>|<\\/${tag}>)`, "g");
    const blocks = Array.from(manifestContent.matchAll(tagRegex));

    for (const block of blocks) {
      const blockText = block[0];
      if (!/android:exported="true"/.test(blockText)) continue;

      const nameMatch = blockText.match(/android:name="([^"]+)"/);
      if (!nameMatch) continue;

      const intentFilters: string[] = [];
      const filterMatches = Array.from(blockText.matchAll(/<intent-filter[^>]*>([\s\S]*?)<\/intent-filter>/g));
      for (const fm of filterMatches) {
        const actions = Array.from(fm[1].matchAll(/<action\s+android:name="([^"]+)"/g)).map((a) => a[1]);
        intentFilters.push(...actions);
      }

      manifest.exportedComponents.push({
        name: nameMatch[1],
        type,
        intentFilters,
      });
    }
  }

  // Deep links from BROWSABLE VIEW intent filters
  const activityBlocks = Array.from(manifestContent.matchAll(/<activity[\s\S]*?(?:\/>|<\/activity>)/g));
  for (const aBlock of activityBlocks) {
    const blockText = aBlock[0];
    const activityNameMatch = blockText.match(/android:name="([^"]+)"/);
    if (!activityNameMatch) continue;
    const activityName = activityNameMatch[1];

    const filterBlocks = Array.from(blockText.matchAll(/<intent-filter[^>]*>([\s\S]*?)<\/intent-filter>/g));
    for (const fb of filterBlocks) {
      const filterText = fb[1];
      if (!/<action\s+android:name="android\.intent\.action\.VIEW"/.test(filterText)) continue;
      if (!/<category\s+android:name="android\.intent\.category\.BROWSABLE"/.test(filterText)) continue;

      const dataMatches = Array.from(filterText.matchAll(/<data\s+([^/>]+)\/?>/g));

      let schemes: string[] = [];
      let hosts: string[] = [];
      let paths: string[] = [];

      for (const dm of dataMatches) {
        const attrs = dm[1];
        const schemeMatch = attrs.match(/android:scheme="([^"]+)"/);
        const hostMatch = attrs.match(/android:host="([^"]+)"/);
        const pathMatch = attrs.match(/android:path(?:Prefix|Pattern)?\s*=\s*"([^"]+)"/);

        if (schemeMatch && !schemes.includes(schemeMatch[1])) schemes.push(schemeMatch[1]);
        if (hostMatch && !hosts.includes(hostMatch[1])) hosts.push(hostMatch[1]);
        if (pathMatch && !paths.includes(pathMatch[1])) paths.push(pathMatch[1]);
      }

      if (schemes.length === 0) schemes = [""];
      if (hosts.length === 0) hosts = [""];
      if (paths.length === 0) paths = [""];

      for (const scheme of schemes) {
        for (const host of hosts) {
          for (const path of paths) {
            deepLinks.push({ scheme, host, pathPattern: path || null, activity: activityName });
            if (scheme && host) {
              manifest.deepLinks.push({ scheme, host, path: path || "" });
            }
          }
        }
      }
    }
  }

  log.info(`Manifest: ${manifest.permissions.length} permissions, ` +
    `${manifest.exportedComponents.length} exported components, ${deepLinks.length} deep links`);

  return { manifest, deepLinks, buildInfo, packageName };
}

async function extractWebviewIssues(fileContents: Map<string, string>): Promise<IntelReport["security"]["webviewIssues"]> {
  const issues: IntelReport["security"]["webviewIssues"] = [];

  const patterns: Array<{ pattern: RegExp; issue: string }> = [
    { pattern: /setJavaScriptEnabled\(\s*true\s*\)/, issue: "JavaScript enabled in WebView" },
    { pattern: /setAllowFileAccess\(\s*true\s*\)/, issue: "File access allowed in WebView" },
    { pattern: /setAllowFileAccessFromFileURLs\(\s*true\s*\)/, issue: "File URL access from file URLs allowed" },
    { pattern: /setAllowUniversalAccessFromFileURLs\(\s*true\s*\)/, issue: "Universal file access allowed" },
    { pattern: /setMixedContentMode\(\s*(?:WebSettings\.)?MIXED_CONTENT_ALWAYS_ALLOW\s*\)/, issue: "Mixed content always allowed" },
    { pattern: /addJavascriptInterface\(/, issue: "JavaScript interface exposed to WebView" },
    { pattern: /setAllowContentAccess\(\s*true\s*\)/, issue: "Content access allowed in WebView" },
  ];

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;
    for (const { pattern, issue } of patterns) {
      if (pattern.test(content)) {
        issues.push({ file: shortFile, issue });
      }
    }
  }

  return issues;
}

async function extractSqlInjection(fileContents: Map<string, string>): Promise<IntelReport["security"]["sqlInjection"]> {
  const issues: IntelReport["security"]["sqlInjection"] = [];

  // Raw SQL built with string concatenation
  const sqlPatterns = [
    /rawQuery\(\s*"[^"]*"\s*\+\s*\w+/g,
    /execSQL\(\s*"[^"]*"\s*\+\s*\w+/g,
    /query\([^)]*"[^"]*"\s*\+\s*\w+/g,
    /(?:SELECT|INSERT|UPDATE|DELETE)\s+[^"]*"\s*\+\s*\w+/g,
  ];

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;
    for (const pattern of sqlPatterns) {
      const matches = Array.from(content.matchAll(pattern));
      for (const m of matches) {
        issues.push({ file: shortFile, query: m[0].substring(0, 200) });
      }
    }
  }

  return issues;
}

// ─── 4. Data Models & Storage ────────────────────────────────────

async function extractStorage(fileContents: Map<string, string>): Promise<IntelReport["storage"]> {
  const result: IntelReport["storage"] = {
    sharedPrefsKeys: [],
    databases: [],
    allModels: [],
  };

  const seenPrefsKeys = new Set<string>();
  const seenModels = new Set<string>();

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;

    // SharedPreferences keys
    const prefPatterns: Array<{ pattern: RegExp; type: string }> = [
      { pattern: /getString\(\s*"([^"]+)"/g, type: "String" },
      { pattern: /getInt\(\s*"([^"]+)"/g, type: "int" },
      { pattern: /getLong\(\s*"([^"]+)"/g, type: "long" },
      { pattern: /getFloat\(\s*"([^"]+)"/g, type: "float" },
      { pattern: /getBoolean\(\s*"([^"]+)"/g, type: "boolean" },
      { pattern: /putString\(\s*"([^"]+)"/g, type: "String" },
      { pattern: /putInt\(\s*"([^"]+)"/g, type: "int" },
      { pattern: /putLong\(\s*"([^"]+)"/g, type: "long" },
      { pattern: /putFloat\(\s*"([^"]+)"/g, type: "float" },
      { pattern: /putBoolean\(\s*"([^"]+)"/g, type: "boolean" },
      { pattern: /edit\(\)\.put\w+\(\s*"([^"]+)"/g, type: "unknown" },
    ];

    for (const { pattern, type } of prefPatterns) {
      const matches = Array.from(content.matchAll(pattern));
      for (const m of matches) {
        if (!seenPrefsKeys.has(m[1])) {
          seenPrefsKeys.add(m[1]);
          result.sharedPrefsKeys.push({ key: m[1], type, file: shortFile });
        }
      }
    }

    // Room @Entity / @Database
    if (/@Entity/i.test(content)) {
      const tableNameMatch = content.match(/@Entity\(\s*(?:tableName\s*=\s*)?"([^"]+)"/);
      const tableName = tableNameMatch ? tableNameMatch[1] : shortFile.replace(/\.java$|\.kt$/, "");
      const existingDb = result.databases.find((d) => d.tables.includes(tableName));
      if (!existingDb) {
        let db = result.databases.find((d) => d.name === "room_database");
        if (!db) {
          db = { name: "room_database", version: null, tables: [] };
          result.databases.push(db);
        }
        db.tables.push(tableName);
      }
    }

    if (/@Database/i.test(content)) {
      const versionMatch = content.match(/version\s*=\s*(\d+)/);
      if (versionMatch) {
        const db = result.databases.find((d) => d.name === "room_database");
        if (db) {
          db.version = parseInt(versionMatch[1], 10);
        } else {
          result.databases.push({ name: "room_database", version: parseInt(versionMatch[1], 10), tables: [] });
        }
      }
    }

    // Raw CREATE TABLE statements
    const createTableMatches = Array.from(content.matchAll(/CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["'`]?(\w+)["'`]?/gi));
    for (const m of createTableMatches) {
      let db = result.databases.find((d) => d.name === "sqlite");
      if (!db) {
        db = { name: "sqlite", version: null, tables: [] };
        result.databases.push(db);
      }
      if (!db.tables.includes(m[1])) db.tables.push(m[1]);
    }

    // ALL @SerializedName models (not just request/response ones)
    if (content.includes("@SerializedName")) {
      const className = shortFile.replace(/\.java$|\.kt$/, "");
      if (seenModels.has(className)) continue;

      const fields: IntelReport["storage"]["allModels"][0]["fields"] = [];
      const fieldMatches = Array.from(
        content.matchAll(
          /@SerializedName\(\s*(?:"([^"]+)"|\w+\.\w+)\s*\)\s*(?:@\w+(?:\([^)]*\))?\s*)*(?:private|public|protected)?\s*(?:final\s+)?(?:var\s+|val\s+)?(?:(\w+(?:<[^>]+>)?)\s+)?(\w+)/g,
        ),
      );
      for (const m of fieldMatches) {
        fields.push({
          serializedName: m[1] ?? "<constant>",
          type: m[2] ?? "unknown",
          name: m[3] ?? "unknown",
        });
      }

      if (fields.length > 0) {
        seenModels.add(className);
        result.allModels.push({ name: className, file: shortFile, fields });
      }
    }
  }

  log.info(`Storage: ${result.sharedPrefsKeys.length} prefs keys, ` +
    `${result.databases.length} databases, ${result.allModels.length} models`);

  return result;
}

// ─── 5. Build & Developer Info ───────────────────────────────────

async function extractBuildInfo(
  fileContents: Map<string, string>,
  manifestBuildInfo: Partial<IntelReport["buildInfo"]>,
  outputDir: string,
): Promise<IntelReport["buildInfo"]> {
  const result: IntelReport["buildInfo"] = {
    applicationId: null,
    versionName: manifestBuildInfo.versionName ?? null,
    versionCode: manifestBuildInfo.versionCode ?? null,
    buildType: null,
    isDebug: false,
    customFields: {},
    targetSdk: manifestBuildInfo.targetSdk ?? null,
    minSdk: manifestBuildInfo.minSdk ?? null,
  };

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;

    if (shortFile === "BuildConfig.java" || shortFile === "BuildConfig.kt") {
      const appIdMatch = content.match(/APPLICATION_ID\s*=\s*"([^"]+)"/);
      if (appIdMatch) result.applicationId = appIdMatch[1];

      const versionNameMatch = content.match(/VERSION_NAME\s*=\s*"([^"]+)"/);
      if (versionNameMatch) result.versionName = versionNameMatch[1];

      const versionCodeMatch = content.match(/VERSION_CODE\s*=\s*(\d+)/);
      if (versionCodeMatch) result.versionCode = versionCodeMatch[1];

      const buildTypeMatch = content.match(/BUILD_TYPE\s*=\s*"([^"]+)"/);
      if (buildTypeMatch) result.buildType = buildTypeMatch[1];

      const debugMatch = content.match(/DEBUG\s*=\s*(true|false)/);
      if (debugMatch) result.isDebug = debugMatch[1] === "true";

      // All custom BuildConfig fields
      const allFields = Array.from(
        content.matchAll(/(?:public\s+)?static\s+final\s+(\w+)\s+(\w+)\s*=\s*(?:"([^"]+)"|(\d+)|(true|false))/g),
      );
      for (const m of allFields) {
        const fieldName = m[2];
        const value = m[3] ?? m[4] ?? m[5];
        if (
          !["APPLICATION_ID", "VERSION_NAME", "VERSION_CODE", "BUILD_TYPE", "DEBUG"].includes(fieldName) &&
          value !== undefined
        ) {
          result.customFields[fieldName] = value;
        }
      }
    }

    // Developer emails (skip schema/framework noise)
    const emailMatches = Array.from(content.matchAll(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g));
    for (const m of emailMatches) {
      const email = m[0];
      if (
        !/example\.com|android\.com|google\.com|apache\.org|w3\.org|xml\.org|schema\.org/i.test(email) &&
        !email.startsWith("xmlns")
      ) {
        if (!result.customFields[`developer_email_${email}`]) {
          result.customFields[`developer_email_${email}`] = shortFile;
        }
      }
    }
  }

  // ProGuard/R8 rules
  const proguardFiles = await findResourceFiles(outputDir, [".pro", ".cfg"]);
  for (const pf of proguardFiles) {
    const content = await readFileSafe(pf);
    if (!content) continue;
    const keepMatches = Array.from(content.matchAll(/-keep\s+(?:class\s+)?([^\s{]+)/g));
    for (const m of keepMatches) {
      result.customFields[`proguard_keep_${m[1]}`] = pf.split("/").pop() ?? pf;
    }
    const dontWarnMatches = Array.from(content.matchAll(/-dontwarn\s+([^\s]+)/g));
    for (const m of dontWarnMatches) {
      result.customFields[`proguard_dontwarn_${m[1]}`] = pf.split("/").pop() ?? pf;
    }
  }

  return result;
}

// ─── 6. Feature Flags & Remote Config ────────────────────────────

async function extractFeatureFlags(fileContents: Map<string, string>): Promise<IntelReport["featureFlags"]> {
  const flags: IntelReport["featureFlags"] = [];
  const seenFlags = new Set<string>();

  for (const [file, content] of Array.from(fileContents.entries())) {
    const shortFile = file.split("/").pop() ?? file;

    // Firebase Remote Config keys
    const remoteConfigMatches = Array.from(
      content.matchAll(/(?:getRemoteConfig|remoteConfig|firebaseRemoteConfig)\s*(?:\(\))?\s*\.(?:getString|getBoolean|getLong|getDouble|getValue)\(\s*"([^"]+)"/g),
    );
    for (const m of remoteConfigMatches) {
      if (!seenFlags.has(m[1])) {
        seenFlags.add(m[1]);
        flags.push({ name: m[1], defaultValue: null, source: shortFile });
      }
    }

    // Feature flag enums
    if (/FeatureFlag|FeatureToggle|Feature\s*\{/i.test(shortFile) || /enum\s+\w*Feature\w*/i.test(content)) {
      const enumMatches = Array.from(content.matchAll(/(?:enum|object)\s+(\w*[Ff]eature\w*)\s*\{([\s\S]*?)\}/g));
      for (const m of enumMatches) {
        const enumBody = m[2];
        const valueMatches = Array.from(enumBody.matchAll(/(\w+)\s*(?:\(|,|;)/g));
        for (const v of valueMatches) {
          const flagName = v[1];
          if (!seenFlags.has(flagName) && !/^(?:companion|override|fun|val|var|private|public)$/i.test(flagName)) {
            seenFlags.add(flagName);
            flags.push({ name: flagName, defaultValue: null, source: shortFile });
          }
        }
      }
    }

    // Flag-style string constants
    const flagConstMatches = Array.from(
      content.matchAll(/(?:FEATURE_|TOGGLE_|FLAG_|EXPERIMENT_)(\w+)\s*=\s*"([^"]+)"/g),
    );
    for (const m of flagConstMatches) {
      const flagName = m[2] || m[1];
      if (!seenFlags.has(flagName)) {
        seenFlags.add(flagName);
        flags.push({ name: flagName, defaultValue: null, source: shortFile });
      }
    }

    // A/B test identifiers — strict: must be a string assignment
    const abTestMatches = Array.from(
      content.matchAll(/(?:abTest|ab_test|experiment)(?:Id|Name|Key)\w*\s*=\s*"([a-zA-Z0-9_.-]+)"/gi),
    );
    for (const m of abTestMatches) {
      if (!seenFlags.has(m[1]) && m[1].length > 3) {
        seenFlags.add(m[1]);
        flags.push({ name: m[1], defaultValue: null, source: shortFile });
      }
    }

    // Remote config defaults map
    if (/[Rr]emote[Cc]onfig|[Dd]efaults?Map|setDefaults/i.test(content) && /firebase|remoteConfig/i.test(content)) {
      const defaultsMatches = Array.from(
        content.matchAll(/put\(\s*"([^"]+)"\s*,\s*(?:"([^"]+)"|(\d+)|(true|false))\s*\)/g),
      );
      for (const m of defaultsMatches) {
        const key = m[1];
        const value = m[2] ?? m[3] ?? m[4];
        if (
          !seenFlags.has(key) &&
          key.length > 3 &&
          !/^(?:Content-Type|Accept|Authorization|[A-Z]{2,3}T?)$/i.test(key) &&
          !/^[A-Z]{2,4}$/.test(key)
        ) {
          seenFlags.add(key);
          flags.push({ name: key, defaultValue: value ?? null, source: shortFile });
        }
      }
    }
  }

  return flags;
}

// ─── Main Entry ──────────────────────────────────────────────────

export async function extractIntel(outputDir: string): Promise<IntelReport> {
  log.info(`Extracting intel from decompiled APK: ${outputDir}`);

  try {
    await access(outputDir);
  } catch {
    log.error(`Directory not found: ${outputDir}`);
    return createEmptyReport(outputDir);
  }

  const stringsXmlPath = join(outputDir, "resources", "res", "values", "strings.xml");
  let stringsXml = await readFileSafe(stringsXmlPath);
  if (!stringsXml) {
    // apktool layout: res/values/strings.xml directly under the root
    stringsXml = await readFileSafe(join(outputDir, "res", "values", "strings.xml"));
  }

  const sourcesDir = join(outputDir, "sources");
  const javaFiles = await findAllJavaFiles(sourcesDir);
  log.info(`Found ${javaFiles.length} source files`);

  const fileContents = new Map<string, string>();
  for (const file of javaFiles) {
    const content = await readFileSafe(file);
    if (content) fileContents.set(file, content);
  }

  const resourceFiles = await findResourceFiles(join(outputDir, "resources"), [".xml"]);

  const sdkKeys = await extractSdkKeys(stringsXml, fileContents);
  const infrastructure = await extractInfrastructure(fileContents, stringsXml, resourceFiles);
  const networkConfig = await extractNetworkSecurityConfig(outputDir);
  const { manifest, deepLinks, buildInfo: manifestBuildInfo, packageName } = await extractManifestSecurity(outputDir);
  const webviewIssues = await extractWebviewIssues(fileContents);
  const sqlInjection = await extractSqlInjection(fileContents);
  const storage = await extractStorage(fileContents);
  const buildInfo = await extractBuildInfo(fileContents, manifestBuildInfo, outputDir);
  const featureFlags = await extractFeatureFlags(fileContents);

  const report: IntelReport = {
    appName: outputDir.split("/").pop() ?? "unknown",
    packageName,
    analyzedAt: new Date().toISOString(),
    sdkKeys,
    infrastructure,
    security: {
      networkConfig,
      manifest,
      webviewIssues,
      sqlInjection,
    },
    storage,
    buildInfo,
    deepLinks,
    featureFlags,
  };

  return report;
}

function createEmptyReport(outputDir: string): IntelReport {
  return {
    appName: outputDir.split("/").pop() ?? "unknown",
    packageName: "unknown",
    analyzedAt: new Date().toISOString(),
    sdkKeys: {
      google: { mapsApiKey: null, appId: null, clientId: null, crashReportingKey: null },
      firebase: { databaseUrl: null, storageBucket: null, projectId: null, senderId: null },
      facebook: { appId: null, clientToken: null },
      sentry: { dsn: null },
      stripe: { publishableKey: null, secretKey: null },
      analytics: [],
      other: [],
    },
    infrastructure: { allUrls: [], awsResources: [], gcpResources: [], stagingUrls: [], adminUrls: [], cmsEndpoints: [], cdnDomains: [] },
    security: {
      networkConfig: { cleartextAllowed: false, certPinning: false, pinnedDomains: [], debugOverrides: false, trustAnchors: [] },
      manifest: { allowBackup: false, debuggable: false, cleartextTraffic: false, exportedComponents: [], permissions: [], deepLinks: [] },
      webviewIssues: [],
      sqlInjection: [],
    },
    storage: { sharedPrefsKeys: [], databases: [], allModels: [] },
    buildInfo: { applicationId: null, versionName: null, versionCode: null, buildType: null, isDebug: false, customFields: {}, targetSdk: null, minSdk: null },
    deepLinks: [],
    featureFlags: [],
  };
}
