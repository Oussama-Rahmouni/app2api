/**
 * Framework Detector — identifies what tech stack an APK uses
 * and routes to the correct analysis strategy.
 *
 * Detects: Java/Kotlin, React Native, Flutter, Cordova/Ionic, Xamarin, Unity
 */

import { execSync } from "node:child_process";
import { access, readdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { createLogger } from "./logger.js";

const log = createLogger("framework-detector");

export type Framework =
  | "java-kotlin"
  | "react-native"
  | "flutter"
  | "cordova"
  | "xamarin"
  | "unity-mono"
  | "unity-il2cpp"
  | "unknown";

export interface FrameworkReport {
  framework: Framework;
  difficulty: "trivial" | "easy" | "medium" | "hard";
  tool: string;
  codeLocation: string;
  extractedDir: string;
  quickFindings: {
    urls: string[];
    secrets: string[];
    apiKeys: string[];
  };
}

async function exists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function quickStrings(path: string, patterns: string): string[] {
  try {
    const out = execSync(
      `strings "${path}" 2>/dev/null | grep -Ei "${patterns}" | head -30`,
      { encoding: "utf-8", timeout: 15_000 },
    );
    return out.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

function quickGrep(dir: string, pattern: string, ext: string): string[] {
  try {
    const out = execSync(
      `grep -r --include="*.${ext}" -ohE "${pattern}" "${dir}" 2>/dev/null | sort -u | head -30`,
      { encoding: "utf-8", timeout: 15_000 },
    );
    return out.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

/** Detect the framework of an already-extracted APK directory. */
export async function detectFrameworkInDir(extractDir: string): Promise<FrameworkReport> {
  const quickFindings = { urls: [] as string[], secrets: [] as string[], apiKeys: [] as string[] };

  // React Native
  const rnBundle = join(extractDir, "assets", "index.android.bundle");
  if (await exists(rnBundle)) {
    log.info("react-native detected — JS bundle found");
    quickFindings.urls = quickGrep(extractDir, "https?://[a-zA-Z0-9.-]+\\.[a-z]{2,}", "bundle");
    quickFindings.secrets = quickGrep(extractDir, "(api_key|apikey|secret|token|bearer)", "bundle");
    return {
      framework: "react-native",
      difficulty: "easy",
      tool: "js beautifier + grep",
      codeLocation: "assets/index.android.bundle",
      extractedDir: extractDir,
      quickFindings,
    };
  }

  // Cordova / Ionic
  const wwwDir = join(extractDir, "assets", "www");
  if (await exists(wwwDir)) {
    log.info("cordova detected — web app bundle found");
    quickFindings.urls = quickGrep(wwwDir, "https?://[a-zA-Z0-9.-]+\\.[a-z]{2,}", "js");
    quickFindings.secrets = quickGrep(wwwDir, "(api_key|apikey|secret|token|bearer)", "js");
    return {
      framework: "cordova",
      difficulty: "trivial",
      tool: "text editor / grep",
      codeLocation: "assets/www/",
      extractedDir: extractDir,
      quickFindings,
    };
  }

  // Flutter (check every ABI, not just arm64)
  const abis = ["arm64-v8a", "armeabi-v7a", "x86_64", "x86"];
  for (const abi of abis) {
    const flutterSo = join(extractDir, "lib", abi, "libflutter.so");
    const appSo = join(extractDir, "lib", abi, "libapp.so");
    if ((await exists(flutterSo)) || (await exists(appSo))) {
      log.info("flutter detected — Dart AOT binary found");
      if (await exists(appSo)) {
        quickFindings.urls = quickStrings(appSo, "https?://");
        quickFindings.secrets = quickStrings(appSo, "api_key|secret|token|bearer|password");
      }
      return {
        framework: "flutter",
        difficulty: "hard",
        tool: "blutter / reFlutter / frida + mitmproxy",
        codeLocation: `lib/${abi}/libapp.so`,
        extractedDir: extractDir,
        quickFindings,
      };
    }
  }

  // Xamarin
  if (await exists(join(extractDir, "assemblies"))) {
    log.info("xamarin detected — .NET assemblies found");
    return {
      framework: "xamarin",
      difficulty: "medium",
      tool: "ilspycmd (dotnet tool install -g ilspycmd)",
      codeLocation: "assemblies/*.dll",
      extractedDir: extractDir,
      quickFindings,
    };
  }

  // Unity
  const managedDir = join(extractDir, "assets", "bin", "Data", "Managed");
  if (await exists(managedDir)) {
    log.info("unity-mono detected — managed .NET DLLs found");
    return {
      framework: "unity-mono",
      difficulty: "medium",
      tool: "ilspycmd",
      codeLocation: "assets/bin/Data/Managed/*.dll",
      extractedDir: extractDir,
      quickFindings,
    };
  }

  for (const abi of abis) {
    const il2cppSo = join(extractDir, "lib", abi, "libil2cpp.so");
    if (await exists(il2cppSo)) {
      log.info("unity-il2cpp detected — native compiled");
      quickFindings.urls = quickStrings(il2cppSo, "https?://");
      return {
        framework: "unity-il2cpp",
        difficulty: "hard",
        tool: "Il2CppDumper + Ghidra",
        codeLocation: `lib/${abi}/libil2cpp.so`,
        extractedDir: extractDir,
        quickFindings,
      };
    }
  }

  // Default: Java/Kotlin native
  log.info("java-kotlin app detected (no cross-platform framework markers)");
  return {
    framework: "java-kotlin",
    difficulty: "easy",
    tool: "jadx",
    codeLocation: "classes.dex (decompile with jadx)",
    extractedDir: extractDir,
    quickFindings,
  };
}

/** Detect framework from an APK file or an already-extracted directory. */
export async function detectFramework(input: string): Promise<FrameworkReport> {
  const inputStat = await stat(input).catch(() => null);
  if (!inputStat) throw new Error(`Input not found: ${input}`);

  if (inputStat.isDirectory()) {
    return detectFrameworkInDir(input);
  }

  // APK file — it's a zip; extract the raw tree for marker checks.
  const extractDir = input.replace(/\.(apk|xapk)$/i, "_raw");
  if (!(await exists(extractDir))) {
    log.info("Extracting APK...");
    execSync(`unzip -q -o "${input}" -d "${extractDir}"`, {
      encoding: "utf-8",
      timeout: 120_000,
    });
  }

  return detectFrameworkInDir(extractDir);
}
