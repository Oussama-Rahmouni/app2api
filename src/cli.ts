#!/usr/bin/env node
/**
 * app2api — CLI entry point.
 *
 * Subcommands:
 *   analyze <apk-or-dir>   Full static pipeline → ApiSpec JSON + report.md
 *   detect <apk-or-dir>    Framework detection only
 *   flutter <apk>          Flutter libapp.so string extraction
 *   dynamic --apk <apk> --domain <d>   Live capture via frida + mitmproxy
 *   doctor                 Probe external tools
 */

import { runPipeline } from "./pipeline.js";
import { detectFramework } from "./framework-detector.js";
import { analyzeFlutterApp } from "./flutter/libapp-extractor.js";
import { extractDynamic } from "./dynamic/pipeline/dynamic-extractor.js";
import { ADB } from "./dynamic/adb.js";
import { runDoctor } from "./doctor.js";
import { createLogger } from "./logger.js";

const log = createLogger("cli");

const USAGE = `app2api — APK in, API spec out

Usage:
  app2api analyze <app.apk|decompiled-dir> [--output <dir>] [--workdir <dir>]
  app2api detect <app.apk|extracted-dir>
  app2api flutter <app.apk|app.xapk> [--reflutter] [--min-length 8] [--keep] [--output <dir>]
  app2api dynamic --apk <app.apk> --domain <example.com> [options]
  app2api dynamic --list-devices
  app2api doctor

dynamic options:
  --time <seconds>       Capture duration (default: 60)
  --device <serial>      ADB device serial (default: first available)
  --no-mitm              Disable the mitmproxy layer
  --no-ssl               Disable native SSL hooks (faster start, breaks Flutter capture)
  --frida-server <path>  Push this frida-server binary to the device first
  --output <dir>         Output directory (default: ./output/dynamic)

Notes:
  - Bring your own APK: adb pull from your device, or apkeep.
  - Static analysis of a decompiled directory needs no external tools.
  - Run "app2api doctor" to check your setup.
`;

/** Hand-rolled arg parser: `--key value`, `--flag`, and `--no-flag`. */
export function parseArgs(argv: string[]): Record<string, string | boolean> {
  const args: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith("--no-")) {
      args[a.slice(5)] = false;
    } else if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = argv[i + 1];
      if (next && !next.startsWith("--")) {
        args[key] = next;
        i++;
      } else {
        args[key] = true;
      }
    }
  }
  return args;
}

async function cmdAnalyze(argv: string[]): Promise<void> {
  const positional = argv.filter((a) => !a.startsWith("--"));
  const input = positional[0];
  if (!input) {
    console.error("Usage: app2api analyze <app.apk|decompiled-dir> [--output <dir>]");
    process.exit(1);
  }
  const args = parseArgs(argv);
  const { spec, outDir } = await runPipeline(input, {
    outputDir: args["output"] as string | undefined,
    workDir: args["workdir"] as string | undefined,
  });

  console.log(`\nSpec:    ${outDir}/api-spec.json`);
  console.log(`Report:  ${outDir}/report.md`);
  console.log(`\nBase URL: ${spec.baseUrl ?? "NOT FOUND"}`);
  console.log(`Auth:     ${spec.authentication.type} (client_id: ${spec.authentication.clientId ?? "?"})`);
  console.log(`Endpoints: ${spec.endpoints.length}`);
  if (spec.endpoints.length > 0) {
    for (const ep of spec.endpoints.slice(0, 10)) {
      console.log(`  ${ep.authenticated ? "[AUTH]  " : "[PUBLIC]"} ${ep.method} ${ep.fullUrl}`);
    }
  }
}

async function cmdDetect(argv: string[]): Promise<void> {
  const input = argv.filter((a) => !a.startsWith("--"))[0];
  if (!input) {
    console.error("Usage: app2api detect <app.apk|extracted-dir>");
    process.exit(1);
  }
  const report = await detectFramework(input);
  console.log(`Framework:     ${report.framework}`);
  console.log(`Difficulty:    ${report.difficulty}`);
  console.log(`Tool:          ${report.tool}`);
  console.log(`Code location: ${report.codeLocation}`);
  if (report.quickFindings.urls.length > 0) {
    console.log(`\nURLs (${report.quickFindings.urls.length}):`);
    report.quickFindings.urls.forEach((u) => console.log(`  ${u}`));
  }
  if (report.quickFindings.secrets.length > 0) {
    console.log(`\nSecrets/keys (${report.quickFindings.secrets.length}):`);
    report.quickFindings.secrets.forEach((s) => console.log(`  ${s}`));
  }
}

async function cmdFlutter(argv: string[]): Promise<void> {
  const input = argv.filter((a) => !a.startsWith("--"))[0];
  if (!input) {
    console.error("Usage: app2api flutter <app.apk|app.xapk> [--reflutter] [--keep]");
    process.exit(1);
  }
  const args = parseArgs(argv);
  const report = await analyzeFlutterApp(input, {
    minLength: parseInt(String(args["min-length"] ?? "8"), 10),
    reFlutter: args["reflutter"] === true,
    keepWorkDir: args["keep"] === true,
    outputDir: (args["output"] as string | undefined) ?? "./output/flutter",
  });

  console.log(`\nFlutter:    ${report.isFlutter}`);
  console.log(`Obfuscated: ${report.isObfuscated}`);
  console.log(`ABI:        ${report.abi || "n/a"}`);
  console.log(`libapp.so:  ${(report.libappSizeBytes / 1024 / 1024).toFixed(1)} MB`);
  console.log(`Strings:    ${report.stats.totalStrings} → ${report.stats.afterFilter} (filtered)`);
  if (report.baseUrls.length) {
    console.log("\nBase URLs:");
    report.baseUrls.forEach((u) => console.log(`  ${u}`));
  }
  if (report.endpoints.length) {
    console.log("\nEndpoints:");
    report.endpoints.slice(0, 30).forEach((e) => console.log(`  ${e}`));
    if (report.endpoints.length > 30) console.log(`  ... +${report.endpoints.length - 30} more`);
  }
  if (Object.keys(report.headers).length) {
    console.log("\nHeaders:");
    for (const [k, v] of Object.entries(report.headers)) console.log(`  ${k}: ${v}`);
  }
  if (report.userAgents.length) {
    console.log("\nUser Agents:");
    report.userAgents.forEach((ua) => console.log(`  ${ua}`));
  }
  if (report.auth.oauthEndpoints.length) {
    console.log("\nOAuth Endpoints:");
    report.auth.oauthEndpoints.forEach((e) => console.log(`  ${e}`));
  }
}

async function cmdDynamic(argv: string[]): Promise<void> {
  const args = parseArgs(argv);

  if (args["list-devices"]) {
    const devices = ADB.listDevices();
    console.log("ADB devices:");
    if (devices.length === 0) console.log("  (none connected)");
    devices.forEach((d) => console.log(`  ${d.serial}  ${d.state}  ${d.model ?? ""}`));
    return;
  }

  const apk = args["apk"] as string | undefined;
  const domain = args["domain"] as string | undefined;
  if (!apk || !domain) {
    console.error("Usage: app2api dynamic --apk <app.apk> --domain <example.com>");
    process.exit(1);
  }

  const result = await extractDynamic(apk, domain, {
    captureMs: parseInt(String(args["time"] ?? "60"), 10) * 1000,
    deviceSerial: args["device"] as string | undefined,
    mitm: args["mitm"] !== false,
    ssl: args["ssl"] !== false,
    fridaServerPath: args["frida-server"] as string | undefined,
    outputDir: (args["output"] as string | undefined) ?? "./output/dynamic",
  });

  console.log(`\nTotal requests:   ${result.stats.totalRequests}`);
  console.log(`Unique endpoints: ${result.stats.uniqueEndpoints}`);
  console.log(`Cert unpins:      ${result.stats.unpinnedMethods.join(", ") || "none"}`);

  if (Object.keys(result.authHeaders).length > 0) {
    console.log("\nAuth headers:");
    for (const [k, v] of Object.entries(result.authHeaders)) {
      console.log(`  ${k}: ${v.slice(0, 80)}`);
    }
  }
  if (Object.keys(result.commonHeaders).length > 0) {
    console.log("\nCommon headers (replay these):");
    for (const [k, v] of Object.entries(result.commonHeaders)) {
      console.log(`  ${k}: ${v}`);
    }
  }
  if (result.endpoints.length > 0) {
    console.log("\nTop endpoints:");
    result.endpoints.slice(0, 15).forEach((e) => {
      console.log(`  [${e.count}x] ${e.method} ${e.url} → ${e.lastStatus ?? "?"}`);
    });
  }
}

async function main(): Promise<void> {
  const [command, ...rest] = process.argv.slice(2);

  switch (command) {
    case "analyze":
      return cmdAnalyze(rest);
    case "detect":
      return cmdDetect(rest);
    case "flutter":
      return cmdFlutter(rest);
    case "dynamic":
      return cmdDynamic(rest);
    case "doctor":
      console.log(runDoctor());
      return;
    case undefined:
    case "help":
    case "--help":
    case "-h":
      console.log(USAGE);
      return;
    default:
      console.error(`Unknown command: ${command}\n`);
      console.log(USAGE);
      process.exit(1);
  }
}

const isMain = process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href;

if (isMain) {
  main().catch((err) => {
    log.error(`Fatal: ${(err as Error).message}`);
    process.exit(1);
  });
}
