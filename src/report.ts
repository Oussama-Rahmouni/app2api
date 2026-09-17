/**
 * Markdown report generator — renders an ApiSpec + raw reports into a
 * human-readable report.md.
 */

import type { ApiSpec } from "./pipeline.js";
import type { DeepAnalysisReport } from "./apk-deep-analyzer.js";
import type { IntelReport } from "./apk-intel-extractor.js";

function yn(b: boolean): string {
  return b ? "**yes**" : "no";
}

export function generateMarkdownReport(
  spec: ApiSpec,
  deep: DeepAnalysisReport,
  intel: IntelReport,
): string {
  const lines: string[] = [];

  lines.push(`# API Surface Report: ${spec.appName}`);
  lines.push("");
  lines.push(`- Package: \`${spec.packageName}\``);
  lines.push(`- Framework: \`${spec.framework}\``);
  lines.push(`- Generated: ${spec.generatedAt}`);
  lines.push(`- Base URL: ${spec.baseUrl ? `\`${spec.baseUrl}\`` : "_not found_"}`);
  lines.push("");

  // ── Authentication ─────────────────────────────────────────────
  lines.push("## Authentication");
  lines.push("");
  lines.push(`- Type: \`${spec.authentication.type}\``);
  if (spec.authentication.clientId) lines.push(`- Client ID: \`${spec.authentication.clientId}\``);
  if (spec.authentication.clientSecret) lines.push(`- Client Secret: \`${spec.authentication.clientSecret}\``);
  if (spec.authentication.clientSecretEncoded) {
    lines.push(`- Client Secret (encoded): \`${spec.authentication.clientSecretEncoded}\``);
    if (deep.authentication.secretDecodingMethod) {
      lines.push(`- Decoding method: \`${deep.authentication.secretDecodingMethod}\``);
    }
  }
  if (spec.authentication.tokenUrl) lines.push(`- Token URL: \`${spec.authentication.tokenUrl}\``);
  if (spec.authentication.grantTypes.length) lines.push(`- Grant types: ${spec.authentication.grantTypes.map((g) => `\`${g}\``).join(", ")}`);
  if (spec.authentication.apiKey) lines.push(`- API key: \`${spec.authentication.apiKey}\``);
  if (spec.authentication.apiKeyHeader) lines.push(`- API key header: \`${spec.authentication.apiKeyHeader}\``);
  if (spec.authentication.type === "none") lines.push("- _No authentication scheme detected._");
  lines.push("");

  // ── Headers ────────────────────────────────────────────────────
  lines.push("## Headers");
  lines.push("");
  if (spec.userAgent) lines.push(`User-Agent format: \`${spec.userAgent}\``);
  const headerEntries = Object.entries(spec.headers);
  if (headerEntries.length === 0 && !spec.userAgent) {
    lines.push("_No static headers detected._");
  } else {
    for (const [k, v] of headerEntries) {
      lines.push(`- \`${k}: ${v}\``);
    }
  }
  lines.push("");

  // ── Endpoints ──────────────────────────────────────────────────
  lines.push(`## Endpoints (${spec.endpoints.length})`);
  lines.push("");
  if (spec.endpoints.length === 0) {
    lines.push("_No Retrofit-style endpoints recovered._");
  } else {
    lines.push("| Method | Path | Auth | Body |");
    lines.push("|--------|------|------|------|");
    for (const ep of spec.endpoints) {
      lines.push(`| ${ep.method} | \`${ep.path}\` | ${ep.authenticated ? "yes" : "no"} | ${ep.bodyType ?? "—"} |`);
    }
  }
  lines.push("");

  // ── Protection ─────────────────────────────────────────────────
  lines.push("## Protection");
  lines.push("");
  lines.push(`- Bot-protection SDK (DataDome): ${yn(spec.protection.datadome)}${spec.protection.sdkKey ? ` (key: \`${spec.protection.sdkKey}\`)` : ""}`);
  lines.push(`- Cloudflare markers: ${yn(spec.protection.cloudflare)}`);
  lines.push(`- Certificate pinning: ${yn(spec.protection.certPinning)}`);
  if (spec.security.pinnedDomains.length) {
    lines.push(`  - Pinned domains: ${spec.security.pinnedDomains.map((d) => `\`${d}\``).join(", ")}`);
  }
  lines.push(`- Root detection: ${yn(spec.protection.rootDetection)}`);
  lines.push("");

  // ── SDK keys ───────────────────────────────────────────────────
  lines.push("## Third-party SDK Keys");
  lines.push("");
  const sk = spec.sdkKeys;
  let anyKey = false;
  if (sk.googleMapsApiKey) { lines.push(`- Google Maps API key: \`${sk.googleMapsApiKey}\``); anyKey = true; }
  if (sk.firebaseProjectId) { lines.push(`- Firebase project: \`${sk.firebaseProjectId}\``); anyKey = true; }
  if (sk.facebookAppId) { lines.push(`- Facebook App ID: \`${sk.facebookAppId}\``); anyKey = true; }
  if (sk.sentryDsn) { lines.push(`- Sentry DSN: \`${sk.sentryDsn}\``); anyKey = true; }
  if (sk.stripePublishableKey) { lines.push(`- Stripe publishable key: \`${sk.stripePublishableKey}\``); anyKey = true; }
  if (sk.stripeSecretKeyFound) { lines.push(`- Stripe SECRET key embedded in the app — report this`); anyKey = true; }
  for (const a of sk.analytics) { lines.push(`- ${a.provider}: \`${a.key}\``); anyKey = true; }
  for (const o of sk.other) { lines.push(`- ${o.name}: \`${o.value}\` (${o.source})`); anyKey = true; }
  if (!anyKey) lines.push("_None found._");
  lines.push("");

  // ── Security posture ───────────────────────────────────────────
  lines.push("## Security Posture");
  lines.push("");
  lines.push(`- Cleartext HTTP allowed: ${yn(spec.security.cleartextAllowed)}`);
  lines.push(`- Debuggable manifest flag: ${yn(spec.security.manifestDebuggable)}`);
  lines.push(`- allowBackup: ${yn(spec.security.allowBackup)}`);
  lines.push(`- Exported components: ${spec.security.exportedComponents}`);
  lines.push(`- Permissions: ${spec.security.permissions}`);
  lines.push(`- WebView issues: ${spec.security.webviewIssues}`);
  lines.push("");

  // ── Crawler hints ──────────────────────────────────────────────
  lines.push("## Crawler Hints");
  lines.push("");
  lines.push(`- Search endpoint: ${spec.crawlerHints.searchEndpoint ? `\`${spec.crawlerHints.searchEndpoint}\`` : "_not found_"}`);
  lines.push(`- Pagination: ${spec.crawlerHints.paginationMethod ?? "unknown"}`);
  if (spec.crawlerHints.listingFields.length) {
    lines.push(`- Listing fields: ${spec.crawlerHints.listingFields.map((f) => `\`${f}\``).join(", ")}`);
  }
  lines.push("");

  // ── Models ─────────────────────────────────────────────────────
  if (deep.models.length > 0) {
    lines.push(`## Data Models (${deep.models.length})`);
    lines.push("");
    for (const model of deep.models.slice(0, 20)) {
      lines.push(`### ${model.name}`);
      lines.push("");
      for (const f of model.fields) {
        lines.push(`- \`${f.serializedName}\`: ${f.type}`);
      }
      lines.push("");
    }
    if (deep.models.length > 20) {
      lines.push(`_…and ${deep.models.length - 20} more (see deep-analysis.json)._`);
      lines.push("");
    }
  }

  // ── Interceptors ───────────────────────────────────────────────
  if (deep.headers.interceptorChain.length > 0) {
    lines.push("## OkHttp Interceptor Chain");
    lines.push("");
    for (const i of deep.headers.interceptorChain) {
      lines.push(`- \`${i.name}\` (${i.type}, ${i.file})`);
    }
    lines.push("");
    lines.push("Header order matters — replay requests with headers in interceptor order.");
    lines.push("");
  }

  // ── Secret decoding ────────────────────────────────────────────
  if (deep.secretDecoding.length > 0) {
    lines.push("## Secret Decoding");
    lines.push("");
    lines.push("Secrets are encoded at rest and decoded at runtime:");
    lines.push("");
    for (const sd of deep.secretDecoding) {
      lines.push(`- ${sd.decodingMethod} (${sd.file})${sd.decodingKey ? ` — key: \`${sd.decodingKey}\`` : ""}`);
    }
    lines.push("");
  }

  // ── Deep links ─────────────────────────────────────────────────
  if (intel.deepLinks.length > 0) {
    lines.push("## Deep Links");
    lines.push("");
    for (const dl of intel.deepLinks) {
      if (dl.scheme) {
        lines.push(`- \`${dl.scheme}://${dl.host}${dl.pathPattern ?? ""}\` → ${dl.activity}`);
      }
    }
    lines.push("");
  }

  lines.push("---");
  lines.push("_Generated by app2api — static analysis. Verify against live traffic with `app2api dynamic`._");
  lines.push("");

  return lines.join("\n");
}
