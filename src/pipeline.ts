/**
 * Static pipeline — full automated API-surface extraction.
 *
 * Input:  APK/XAPK file, or an already-decompiled directory (jadx output).
 * Output: ApiSpec (machine-readable) + markdown report + raw reports.
 *
 * Chain: detect framework → decompile (if APK) → pattern analysis →
 *        deep analysis → intel extraction → generate spec.
 */

import { existsSync } from "node:fs";
import { mkdir, stat, writeFile } from "node:fs/promises";
import { execSync } from "node:child_process";
import { join, basename } from "node:path";
import { createLogger } from "./logger.js";
import { detectFramework, detectFrameworkInDir, type FrameworkReport } from "./framework-detector.js";
import { analyzeApk } from "./apk-analyzer.js";
import { deepAnalyzeApk, type DeepAnalysisReport } from "./apk-deep-analyzer.js";
import { extractIntel, type IntelReport } from "./apk-intel-extractor.js";
import { generateMarkdownReport } from "./report.js";
import { requireTool, TOOLS } from "./tools.js";
import type { ApkReport } from "./types.js";

const log = createLogger("pipeline");

export interface ApiSpec {
  appName: string;
  packageName: string;
  framework: string;
  generatedAt: string;
  baseUrl: string | null;
  authentication: {
    type: string;
    clientId: string | null;
    clientSecret: string | null;
    clientSecretEncoded: string | null;
    tokenUrl: string | null;
    grantTypes: string[];
    apiKey: string | null;
    apiKeyHeader: string | null;
    oauthFlows: ApkReport["authConfig"]["oauthFlows"];
  };
  headers: Record<string, string>;
  userAgent: string | null;
  endpoints: Array<{
    method: string;
    path: string;
    fullUrl: string;
    authenticated: boolean;
    headers: Record<string, string>;
    bodyType: string | null;
  }>;
  protection: {
    datadome: boolean;
    cloudflare: boolean;
    certPinning: boolean;
    rootDetection: boolean;
    sdkKey: string | null;
  };
  sdkKeys: {
    googleMapsApiKey: string | null;
    firebaseProjectId: string | null;
    facebookAppId: string | null;
    sentryDsn: string | null;
    stripePublishableKey: string | null;
    stripeSecretKeyFound: boolean;
    analytics: Array<{ provider: string; key: string }>;
    other: Array<{ name: string; value: string; source: string }>;
  };
  security: {
    cleartextAllowed: boolean;
    manifestDebuggable: boolean;
    allowBackup: boolean;
    pinnedDomains: string[];
    exportedComponents: number;
    permissions: number;
    webviewIssues: number;
  };
  crawlerHints: {
    searchEndpoint: string | null;
    paginationMethod: string | null;
    listingFields: string[];
  };
}

export function generateSpec(
  basic: ApkReport,
  deep: DeepAnalysisReport,
  intel: IntelReport,
  framework: string,
): ApiSpec {
  const baseUrl = deep.configuration.apiBaseUrl ?? basic.baseUrls[0] ?? null;

  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(deep.headers.staticHeaders)) {
    if (v !== "<dynamic>") {
      headers[k] = v;
    }
  }

  // Determine search endpoint
  let searchEndpoint: string | null = null;
  for (const ep of deep.endpoints) {
    const path = ep.path.toLowerCase();
    if (path.includes("search") || path.includes("finder") || path.includes("listing")) {
      searchEndpoint = ep.path;
    }
  }

  // Pagination hints from response models
  let paginationMethod: string | null = null;
  for (const model of deep.models) {
    for (const field of model.fields) {
      if (field.serializedName === "pivot" || field.serializedName === "cursor") {
        paginationMethod = "cursor";
      } else if (field.serializedName === "offset" || field.serializedName === "page") {
        paginationMethod = "offset";
      }
    }
  }

  // Listing fields from response-ish models
  const listingFields: string[] = [];
  for (const model of deep.models) {
    const n = model.name.toLowerCase();
    if (n.includes("response") || n.includes("ad") || n.includes("listing")) {
      for (const field of model.fields) {
        listingFields.push(field.serializedName);
      }
    }
  }

  return {
    appName: deep.appName,
    packageName: deep.packageName,
    framework,
    generatedAt: new Date().toISOString(),
    baseUrl,
    authentication: {
      type: deep.authentication.type,
      clientId: deep.authentication.clientId,
      clientSecret: deep.authentication.clientSecret,
      clientSecretEncoded: deep.authentication.clientSecretEncoded,
      tokenUrl: deep.authentication.tokenUrl
        ? (baseUrl ? baseUrl + deep.authentication.tokenUrl : deep.authentication.tokenUrl)
        : null,
      grantTypes: deep.authentication.grantTypes,
      apiKey: deep.authentication.apiKeyValue,
      apiKeyHeader: deep.authentication.apiKeyHeader,
      oauthFlows: basic.authConfig.oauthFlows,
    },
    headers,
    userAgent: deep.headers.userAgentFormat,
    endpoints: deep.endpoints.map((ep) => ({
      method: ep.method,
      path: ep.path,
      fullUrl: baseUrl ? `${baseUrl}/${ep.path.replace(/^\//, "")}` : ep.path,
      authenticated: ep.authenticated,
      headers: ep.headers,
      bodyType: ep.bodyType,
    })),
    protection: {
      datadome: !!deep.protection.datadome,
      cloudflare: deep.protection.cloudflare,
      certPinning: !!deep.protection.certPinning || intel.security.networkConfig.certPinning,
      rootDetection: deep.protection.rootDetection,
      sdkKey: deep.protection.datadome?.sdkKey ?? null,
    },
    sdkKeys: {
      googleMapsApiKey: intel.sdkKeys.google.mapsApiKey,
      firebaseProjectId: intel.sdkKeys.firebase.projectId,
      facebookAppId: intel.sdkKeys.facebook.appId,
      sentryDsn: intel.sdkKeys.sentry.dsn,
      stripePublishableKey: intel.sdkKeys.stripe.publishableKey,
      stripeSecretKeyFound: !!intel.sdkKeys.stripe.secretKey,
      analytics: intel.sdkKeys.analytics,
      other: intel.sdkKeys.other,
    },
    security: {
      cleartextAllowed: intel.security.networkConfig.cleartextAllowed || intel.security.manifest.cleartextTraffic,
      manifestDebuggable: intel.security.manifest.debuggable,
      allowBackup: intel.security.manifest.allowBackup,
      pinnedDomains: intel.security.networkConfig.pinnedDomains,
      exportedComponents: intel.security.manifest.exportedComponents.length,
      permissions: intel.security.manifest.permissions.length,
      webviewIssues: intel.security.webviewIssues.length,
    },
    crawlerHints: {
      searchEndpoint,
      paginationMethod,
      listingFields,
    },
  };
}

function decompileWithJadx(apkPath: string, outputDir: string): boolean {
  if (existsSync(outputDir)) {
    log.info(`Reusing existing decompilation: ${outputDir}`);
    return true;
  }

  requireTool("jadx", TOOLS.find((t) => t.name === "jadx")!.installHint);

  log.info("Running jadx decompiler...");
  try {
    execSync(`jadx -d "${outputDir}" "${apkPath}" 2>&1`, {
      encoding: "utf-8",
      timeout: 300_000,
      maxBuffer: 50 * 1024 * 1024,
    });
    return true;
  } catch {
    // jadx exits non-zero on partially-decompilable apps but still produces output
    log.warn("jadx exited with warnings (partial output may still be usable)");
    return existsSync(outputDir);
  }
}

export interface PipelineResult {
  spec: ApiSpec;
  basic: ApkReport;
  deep: DeepAnalysisReport;
  intel: IntelReport;
  framework: FrameworkReport;
  outDir: string;
  decompiledDir: string;
}

export async function runPipeline(
  input: string,
  opts: { outputDir?: string; workDir?: string } = {},
): Promise<PipelineResult> {
  const outputDir = opts.outputDir ?? "./output";
  const workDir = opts.workDir ?? "./apk-output";

  log.info(`Input: ${input}`);

  const inputStat = await stat(input).catch(() => null);
  if (!inputStat) throw new Error(`Input not found: ${input}`);

  // ── Step 1: framework detection ────────────────────────────────
  log.info("Step 1/4: framework detection");
  const fwReport = inputStat.isDirectory()
    ? await detectFrameworkInDir(input)
    : await detectFramework(input);
  log.info(`Framework: ${fwReport.framework} (difficulty: ${fwReport.difficulty})`);

  if (fwReport.framework === "flutter") {
    log.warn("Flutter app — Dart logic lives in libapp.so. See: app2api flutter <apk>");
  }

  // ── Step 2: decompile ──────────────────────────────────────────
  log.info("Step 2/4: decompilation");
  const appName = inputStat.isDirectory()
    ? basename(input.replace(/\/+$/, ""))
    : basename(input).replace(/\.(apk|xapk)$/i, "");
  const decompiledDir = inputStat.isDirectory()
    ? input
    : join(workDir, appName);

  if (!inputStat.isDirectory()) {
    const decompiled = decompileWithJadx(input, decompiledDir);
    if (!decompiled) {
      throw new Error("Decompilation failed — no output produced");
    }
  } else {
    log.info("Directory input — skipping decompile");
  }

  // ── Step 3: analysis ───────────────────────────────────────────
  log.info("Step 3/4: analysis");
  const basicReport = await analyzeApk(decompiledDir, appName);
  const deepReport = await deepAnalyzeApk(decompiledDir);
  const intelReport = await extractIntel(decompiledDir);

  // ── Step 4: spec + reports ─────────────────────────────────────
  log.info("Step 4/4: generating API specification");
  const spec = generateSpec(basicReport, deepReport, intelReport, fwReport.framework);

  const outDir = join(outputDir, appName);
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "api-spec.json"), JSON.stringify(spec, null, 2), "utf-8");
  await writeFile(join(outDir, "deep-analysis.json"), JSON.stringify(deepReport, null, 2), "utf-8");
  await writeFile(join(outDir, "intel.json"), JSON.stringify(intelReport, null, 2), "utf-8");
  await writeFile(join(outDir, "report.md"), generateMarkdownReport(spec, deepReport, intelReport), "utf-8");

  log.info(`Results written to ${outDir}/`);
  log.info(`  api-spec.json      machine-readable API spec`);
  log.info(`  report.md          human report`);
  log.info(`  deep-analysis.json raw deep analysis`);
  log.info(`  intel.json         SDK keys / infra / security intel`);

  log.info("─".repeat(50));
  log.info(`App: ${spec.appName} | framework: ${spec.framework}`);
  log.info(`Base URL: ${spec.baseUrl ?? "NOT FOUND"}`);
  log.info(`Auth: ${spec.authentication.type} | client_id: ${spec.authentication.clientId ?? "?"} | api key: ${spec.authentication.apiKey ?? "?"}`);
  log.info(`Endpoints: ${spec.endpoints.length} | protection: datadome=${spec.protection.datadome} pinning=${spec.protection.certPinning}`);
  log.info("─".repeat(50));

  return { spec, basic: basicReport, deep: deepReport, intel: intelReport, framework: fwReport, outDir, decompiledDir };
}
