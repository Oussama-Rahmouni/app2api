/**
 * External tool discovery — probes binaries on PATH via `<tool> --version`.
 *
 * app2api has zero npm runtime dependencies; it shells out to established
 * RE tooling instead. Everything here degrades gracefully: a missing tool
 * yields an install hint, never a crash.
 */

import { spawnSync } from "node:child_process";

export interface ToolProbe {
  name: string;
  /** Binary invoked for the version probe */
  bin: string;
  installed: boolean;
  version: string | null;
  /** What the tool is used for */
  purpose: string;
  installHint: string;
}

export interface ToolDef {
  name: string;
  bin: string;
  args: string[];
  purpose: string;
  installHint: string;
  requiredFor: "static-apk" | "dynamic" | "flutter-deep" | "optional";
}

export const TOOLS: ToolDef[] = [
  {
    name: "jadx",
    bin: "jadx",
    args: ["--version"],
    purpose: "DEX → Java decompilation (static analysis of APK files)",
    installHint: "https://github.com/skylot/jadx/releases — or: brew install jadx",
    requiredFor: "static-apk",
  },
  {
    name: "apktool",
    bin: "apktool",
    args: ["--version"],
    purpose: "Resource/manifest decoding (alternative/complement to jadx)",
    installHint: "https://apktool.org — or: brew install apktool",
    requiredFor: "optional",
  },
  {
    name: "adb",
    bin: "adb",
    args: ["--version"],
    purpose: "Device communication (install APK, proxy, process control)",
    installHint: "Android platform-tools: https://developer.android.com/tools/releases/platform-tools",
    requiredFor: "dynamic",
  },
  {
    name: "frida",
    bin: "frida",
    args: ["--version"],
    purpose: "Runtime instrumentation (hooks, traffic capture at the Java layer)",
    installHint: "pip install frida-tools",
    requiredFor: "dynamic",
  },
  {
    name: "frida-server",
    bin: "frida-server",
    args: ["--version"],
    purpose: "Device-side frida daemon (checked on the device via adb, not PATH)",
    installHint: "https://github.com/frida/frida/releases — push the android-arm64 build to a rooted device/emulator",
    requiredFor: "dynamic",
  },
  {
    name: "mitmdump",
    bin: "mitmdump",
    args: ["--version"],
    purpose: "mitmproxy CLI — captures traffic that bypasses the Java layer",
    installHint: "pip install mitmproxy",
    requiredFor: "dynamic",
  },
  {
    name: "reFlutter",
    bin: "reFlutter",
    args: ["--version"],
    purpose: "Flutter snapshot reconstruction (deep libapp.so analysis)",
    installHint: "pip install reflutter",
    requiredFor: "flutter-deep",
  },
  {
    name: "strings",
    bin: "strings",
    args: ["--version"],
    purpose: "String extraction from native binaries (libapp.so)",
    installHint: "binutils — apt install binutils / xcode command line tools",
    requiredFor: "optional",
  },
  {
    name: "unzip",
    bin: "unzip",
    args: ["--version"],
    purpose: "APK/XAPK extraction (APKs are zip files)",
    installHint: "apt install unzip / preinstalled on macOS",
    requiredFor: "static-apk",
  },
];

/**
 * Parse a version string out of a tool's `--version` output.
 * Pure function — unit-tested against canned outputs.
 */
export function parseVersionOutput(toolName: string, output: string): string | null {
  const text = output.trim();
  if (!text) return null;

  // First semver-ish token wins; fall back to the first line.
  const versionMatch = text.match(/(\d+\.\d+(?:\.\d+)?(?:[-+.][0-9A-Za-z.-]+)?)/);
  if (versionMatch) return versionMatch[1];

  const firstLine = text.split("\n")[0].trim();
  return firstLine.length > 0 && firstLine.length < 80 ? firstLine : null;
}

export function probeTool(def: ToolDef): ToolProbe {
  try {
    const result = spawnSync(def.bin, def.args, {
      encoding: "utf-8",
      timeout: 10_000,
    });
    if (result.error) throw result.error;
    const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
    return {
      name: def.name,
      bin: def.bin,
      installed: true,
      version: parseVersionOutput(def.name, output),
      purpose: def.purpose,
      installHint: def.installHint,
    };
  } catch {
    return {
      name: def.name,
      bin: def.bin,
      installed: false,
      version: null,
      purpose: def.purpose,
      installHint: def.installHint,
    };
  }
}

export function probeAllTools(): ToolProbe[] {
  return TOOLS.map(probeTool);
}

/** Throw with an actionable message if a required tool is missing. */
export function requireTool(bin: string, installHint: string): void {
  const probe = probeTool({
    name: bin,
    bin,
    args: ["--version"],
    purpose: "",
    installHint,
    requiredFor: "optional",
  });
  if (!probe.installed) {
    throw new Error(
      `Required tool "${bin}" not found on PATH.\nInstall: ${installHint}`,
    );
  }
}
