/**
 * Deep APK Analyzer — goes beyond grep patterns to reconstruct:
 * - Configuration classes with hardcoded URLs and secrets
 * - OkHttp interceptor chains (header order matters)
 * - Retrofit service interfaces (exact endpoints with HTTP methods)
 * - Secret encoding/decoding mechanisms
 * - Bot-protection SDK integrations (detection only)
 * - Authentication flows (OAuth2, API key, bearer)
 * - Request/response model structures (@SerializedName)
 */

import { readdir, readFile, access } from "node:fs/promises";
import { join } from "node:path";
import { createLogger } from "./logger.js";

const log = createLogger("deep-analyzer");

// ─── Types ───────────────────────────────────────────────────────

export interface DeepAnalysisReport {
  appName: string;
  packageName: string;
  analyzedAt: string;
  isFlutter: boolean;
  isReactNative: boolean;

  configuration: {
    apiBaseUrl: string | null;
    otherUrls: Record<string, string>;
    configClass: string | null;
  };

  authentication: {
    type: "oauth2" | "apikey" | "bearer" | "custom" | "none";
    clientId: string | null;
    clientSecret: string | null;
    clientSecretEncoded: string | null;
    secretDecodingMethod: string | null;
    tokenUrl: string | null;
    grantTypes: string[];
    apiKeyHeader: string | null;
    apiKeyValue: string | null;
  };

  headers: {
    interceptorChain: InterceptorInfo[];
    staticHeaders: Record<string, string>;
    userAgentFormat: string | null;
  };

  endpoints: RetrofitEndpoint[];

  protection: {
    datadome: DataDomeInfo | null;
    cloudflare: boolean;
    certPinning: CertPinInfo | null;
    rootDetection: boolean;
  };

  models: ModelInfo[];

  secretDecoding: SecretDecodingInfo[];
}

interface InterceptorInfo {
  name: string;
  type: "network" | "application";
  file: string;
  headersAdded: string[];
  description: string;
}

interface RetrofitEndpoint {
  method: string;
  path: string;
  authenticated: boolean;
  headers: Record<string, string>;
  bodyType: string | null;
  returnType: string | null;
  file: string;
}

interface DataDomeInfo {
  sdkKey: string | null;
  sdkVersion: string | null;
  sdkEndpoint: string;
  customHeaders: Record<string, string>;
}

interface CertPinInfo {
  detected: boolean;
  pins: string[];
  domains: string[];
}

interface ModelInfo {
  name: string;
  file: string;
  fields: { name: string; serializedName: string; type: string }[];
}

interface SecretDecodingInfo {
  encodedValue: string;
  decodingMethod: string;
  decodingKey: string | null;
  file: string;
}

// ─── File Discovery ──────────────────────────────────────────────

async function findJavaFiles(dir: string): Promise<string[]> {
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
        // Skip known noise directories
        if (
          entry.name === "android" ||
          entry.name === "androidx" ||
          entry.name === "google" ||
          entry.name === "kotlin" ||
          entry.name === "kotlinx" ||
          entry.name === "okhttp3" ||
          entry.name === "retrofit2" ||
          entry.name === "com" // revisit com/ selectively
        ) {
          if (entry.name === "com") {
            await walkSelective(full);
          }
          continue;
        }
        await walk(full);
      } else if (entry.name.endsWith(".java") || entry.name.endsWith(".kt")) {
        files.push(full);
      }
    }
  }

  async function walkSelective(d: string) {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return;
    }
    for (const entry of entries) {
      const full = join(d, entry.name);
      if (entry.isDirectory()) {
        // Skip framework/library dirs under com/
        if (
          entry.name === "google" ||
          entry.name === "android" ||
          entry.name === "facebook" ||
          entry.name === "bumptech" ||
          entry.name === "jakewharton" ||
          entry.name === "squareup" ||
          entry.name === "airbnb"
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

async function readFileSafe(path: string): Promise<string> {
  try {
    return await readFile(path, "utf-8");
  } catch {
    return "";
  }
}

// ─── Configuration Analysis ──────────────────────────────────────

async function findConfiguration(
  files: string[],
  fileContents: Map<string, string>,
): Promise<DeepAnalysisReport["configuration"]> {
  const result: DeepAnalysisReport["configuration"] = {
    apiBaseUrl: null,
    otherUrls: {},
    configClass: null,
  };

  // Find *Prod* / *Production* / *Release* config classes
  const configPatterns = [
    /ConfigurationProd/i,
    /ConfigProduction/i,
    /ProdConfig/i,
    /ReleaseConfig/i,
    /AppConfig/i,
    /ServerConfig/i,
    /ApiConfig/i,
  ];

  for (const file of files) {
    const name = file.split("/").pop() ?? "";
    if (configPatterns.some((p) => p.test(name))) {
      const content = fileContents.get(file) ?? "";
      log.info(`Found config class: ${name}`);
      result.configClass = file;

      // Extract URL fields
      const urlMatches = content.matchAll(
        /(?:private|public|protected)?\s+(?:final\s+)?(?:String|string)\s+(\w*(?:url|base|host|endpoint|domain)\w*)\s*=\s*"(https?:\/\/[^"]+)"/gi,
      );
      for (const m of Array.from(urlMatches)) {
        const fieldName = m[1];
        const url = m[2];
        if (/apiBase|api_base/i.test(fieldName)) {
          result.apiBaseUrl = url;
        }
        result.otherUrls[fieldName] = url;
      }
    }
  }

  // Fallback: search for getApiBaseUrl
  if (!result.apiBaseUrl) {
    for (const [file, content] of Array.from(fileContents.entries())) {
      const match = content.match(
        /getApiBaseUrl\(\)\s*\{[^}]*return\s+(?:this\.)?(\w+)\s*;/,
      );
      if (match) {
        const fieldMatch = content.match(
          new RegExp(`${match[1]}\\s*=\\s*"(https?://[^"]+)"`),
        );
        if (fieldMatch) {
          result.apiBaseUrl = fieldMatch[1];
          result.configClass = file;
        }
      }
    }
  }

  return result;
}

// ─── Authentication Analysis ─────────────────────────────────────

async function findAuthentication(
  fileContents: Map<string, string>,
): Promise<DeepAnalysisReport["authentication"]> {
  const result: DeepAnalysisReport["authentication"] = {
    type: "none",
    clientId: null,
    clientSecret: null,
    clientSecretEncoded: null,
    secretDecodingMethod: null,
    tokenUrl: null,
    grantTypes: [],
    apiKeyHeader: null,
    apiKeyValue: null,
  };

  for (const [file, content] of Array.from(fileContents.entries())) {
    // Hardcoded client_id in OAuth form bodies
    const clientIdMatch = content.match(
      /\.add\(\s*"client_id"\s*,\s*"([^"]+)"\s*\)/,
    );
    if (clientIdMatch) {
      result.clientId = clientIdMatch[1];
      result.type = "oauth2";
      log.info(`Found client_id: "${result.clientId}" in ${file.split("/").pop()}`);
    }

    // grant_type
    const grantMatch = content.match(
      /\.add\(\s*"grant_type"\s*,\s*"([^"]+)"\s*\)/,
    );
    if (grantMatch && !result.grantTypes.includes(grantMatch[1])) {
      result.grantTypes.push(grantMatch[1]);
    }

    // client_secret passed by reference — trace the field
    const secretFormMatch = content.match(
      /\.add\(\s*"client_secret"\s*,\s*(?:this\.)?(\w+)\s*\)/,
    );
    if (secretFormMatch) {
      const fieldName = secretFormMatch[1];
      const fieldValueMatch = content.match(
        new RegExp(`${fieldName}\\s*=\\s*(?:configuration\\.)?get(\\w+)\\(\\)`),
      );
      if (fieldValueMatch) {
        log.info(
          `client_secret comes from: ${fieldValueMatch[1]} in ${file.split("/").pop()}`,
        );
      }
    }

    // Encoded secrets
    const encodedSecretMatch = content.match(
      /oAuthClientSecretValue\s*=\s*"([^"]+)"/,
    );
    if (encodedSecretMatch) {
      result.clientSecretEncoded = encodedSecretMatch[1];
    }

    // Secret decoding helper calls
    const decodeMatch = content.match(
      /(?:SecurityUtils|CryptoUtils|KeyUtils)\.(\w+)\(\s*get\w+\(\)\s*,\s*"([^"]+)"/,
    );
    if (decodeMatch) {
      result.secretDecodingMethod = decodeMatch[1];
      log.info(
        `Secret decoding: ${decodeMatch[1]} with key starting "${decodeMatch[2].substring(0, 10)}..."`,
      );
    }

    // Bearer token pattern
    if (
      /header\(\s*"Authorization"\s*,\s*"Bearer\s/.test(content) ||
      /addHeader\(\s*"Authorization"\s*,\s*"Bearer\s/.test(content)
    ) {
      if (result.type === "none") result.type = "bearer";
    }

    // API key header on Retrofit methods
    const apiKeyHeaderMatch = content.match(
      /@Header\(\s*"(api[_-]?key|x-api-key|apikey)"\s*\)/i,
    );
    if (apiKeyHeaderMatch) {
      result.apiKeyHeader = apiKeyHeaderMatch[1];
      if (result.type === "none") result.type = "apikey";
    }

    // Hardcoded API key values
    const apiKeyValueMatch = content.match(
      /(?:getApiKeyValue|apiKeyValue)\s*\(\)\s*\{[^}]*return\s+"([^"]+)"/,
    );
    if (apiKeyValueMatch) {
      result.apiKeyValue = apiKeyValueMatch[1];
      log.info(`Found API key value: ${result.apiKeyValue}`);
    }

    // Token URL construction
    const tokenUrlMatch = content.match(
      /(?:authenticationUrl|tokenUrl|token_url)\s*=\s*(?:getApiBaseUrl\(\)|(?:this\.)?\w+)\s*\+\s*"([^"]+)"/,
    );
    if (tokenUrlMatch) {
      result.tokenUrl = tokenUrlMatch[1];
    }
  }

  return result;
}

// ─── Interceptor Chain Analysis ──────────────────────────────────

async function findInterceptors(
  fileContents: Map<string, string>,
): Promise<DeepAnalysisReport["headers"]> {
  const result: DeepAnalysisReport["headers"] = {
    interceptorChain: [],
    staticHeaders: {},
    userAgentFormat: null,
  };

  // OkHttpClient builder with interceptor chain
  for (const [file, content] of Array.from(fileContents.entries())) {
    const interceptorMatches = content.matchAll(
      /\.add(?:Network)?Interceptor\(\s*(\w+)\s*\)/g,
    );
    for (const m of Array.from(interceptorMatches)) {
      const type = m[0].includes("NetworkInterceptor") ? "network" as const : "application" as const;
      result.interceptorChain.push({
        name: m[1],
        type,
        file: file.split("/").pop() ?? "",
        headersAdded: [],
        description: "",
      });
    }
  }

  // Header values inside interceptor classes
  for (const [file, content] of Array.from(fileContents.entries())) {
    const fileName = file.split("/").pop() ?? "";
    if (!fileName.includes("Interceptor")) continue;

    const headerMatches = content.matchAll(
      /\.header\(\s*"([^"]+)"\s*,\s*(?:"([^"]+)"|\w+)\s*\)/g,
    );
    for (const m of Array.from(headerMatches)) {
      result.staticHeaders[m[1]] = m[2] ?? "<dynamic>";
    }

    const addHeaderMatches = content.matchAll(
      /\.addHeader\(\s*"([^"]+)"\s*,\s*(?:"([^"]+)"|\w+)\s*\)/g,
    );
    for (const m of Array.from(addHeaderMatches)) {
      result.staticHeaders[m[1]] = m[2] ?? "<dynamic>";
    }

    // User-Agent format constant
    const uaFormatMatch = content.match(
      /USER_AGENT_FORMAT\s*=\s*"([^"]+)"/,
    );
    if (uaFormatMatch) {
      result.userAgentFormat = uaFormatMatch[1];
    }

    // HEADER_ name constants paired with HEADER_*_VALUE constants
    const headerConstMatches = content.matchAll(
      /HEADER_\w+\s*=\s*"([^"]+)"/g,
    );
    for (const m of Array.from(headerConstMatches)) {
      const valueMatch = content.match(
        /HEADER_\w+_VALUE\s*=\s*"([^"]+)"/,
      );
      if (valueMatch) {
        result.staticHeaders[m[1]] = valueMatch[1];
      }
    }
  }

  return result;
}

// ─── Retrofit Service Analysis ───────────────────────────────────

async function findRetrofitEndpoints(
  fileContents: Map<string, string>,
): Promise<RetrofitEndpoint[]> {
  const endpoints: RetrofitEndpoint[] = [];

  for (const [file, content] of Array.from(fileContents.entries())) {
    // Only interface files with Retrofit annotations
    if (!/@(?:GET|POST|PUT|DELETE|PATCH|HEAD)\(/.test(content)) continue;

    const fileName = file.split("/").pop() ?? "";

    const methodMatches = content.matchAll(
      /@(GET|POST|PUT|DELETE|PATCH|HEAD)\(\s*"([^"]+)"\s*\)/g,
    );
    for (const m of Array.from(methodMatches)) {
      const method = m[1];
      const path = m[2];

      const afterAnnotation = content.substring(
        (m.index ?? 0) + m[0].length,
        (m.index ?? 0) + m[0].length + 500,
      );

      // @Header annotations
      const headers: Record<string, string> = {};
      const headerAnnotations = afterAnnotation.matchAll(
        /@Header\(\s*"([^"]+)"\s*\)/g,
      );
      for (const h of Array.from(headerAnnotations)) {
        headers[h[1]] = "<parameter>";
      }

      // @Body type
      let bodyType: string | null = null;
      const bodyMatch = afterAnnotation.match(
        /@Body\s+@?\w*\s*(\w+)\s+\w+/,
      );
      if (bodyMatch) {
        bodyType = bodyMatch[1];
      }

      // Return type
      let returnType: string | null = null;
      const returnMatch = afterAnnotation.match(
        /Single<(?:Response<)?([^>)]+)/,
      );
      if (returnMatch) {
        returnType = returnMatch[1];
      }

      endpoints.push({
        method,
        path,
        authenticated: false,
        headers,
        bodyType,
        returnType,
        file: fileName,
      });

      log.info(`Found endpoint: ${method} ${path} (${fileName})`);
    }
  }

  // Determine authenticated vs unauthenticated from the DI module
  for (const [, content] of Array.from(fileContents.entries())) {
    if (!content.includes("@Provides") || !content.includes("Retrofit")) continue;

    const providerMatches = content.matchAll(
      /@Named\(\s*"(\w+)"\s*\)[^)]*Retrofit[^{]*\{[^}]*create\(\s*(\w+)\.class\s*\)/g,
    );
    for (const m of Array.from(providerMatches)) {
      const qualifier = m[1]; // e.g. "Authenticated" / "Unauthenticated"
      const serviceClass = m[2];

      for (const ep of endpoints) {
        if (ep.file.replace(".java", "").includes(serviceClass.replace("ApiService", ""))) {
          ep.authenticated = qualifier.toLowerCase().includes("authenticated") &&
            !qualifier.toLowerCase().includes("unauthenticated");
        }
      }
    }
  }

  return endpoints;
}

// ─── Protection Detection ────────────────────────────────────────

async function findProtection(
  fileContents: Map<string, string>,
): Promise<DeepAnalysisReport["protection"]> {
  const result: DeepAnalysisReport["protection"] = {
    datadome: null,
    cloudflare: false,
    certPinning: null,
    rootDetection: false,
  };

  for (const [file, content] of Array.from(fileContents.entries())) {
    // DataDome SDK init
    const datadomeKeyMatch = content.match(
      /DataDomeSDK\.with\([^,]+,\s*"([^"]+)"\s*,\s*"([^"]+)"/,
    );
    if (datadomeKeyMatch) {
      result.datadome = {
        sdkKey: datadomeKeyMatch[1],
        sdkVersion: datadomeKeyMatch[2],
        sdkEndpoint: "https://api-sdk.datadome.co/sdk/",
        customHeaders: {},
      };
      log.info(
        `DataDome SDK detected: key=${datadomeKeyMatch[1]}, version=${datadomeKeyMatch[2]}`,
      );
    }

    // DataDome custom headers
    if (result.datadome) {
      const ddHeaderMatch = content.match(
        /HEADER_ACCEPT_DATADOME\s*=\s*"([^"]+)"[\s\S]*?HEADER_ACCEPT_DATADOME_VALUE\s*=\s*"([^"]+)"/,
      );
      if (ddHeaderMatch) {
        result.datadome.customHeaders[ddHeaderMatch[1]] = ddHeaderMatch[2];
      }
    }

    // Cloudflare markers
    if (/cloudflare|cf-ray|__cfduid/i.test(content)) {
      result.cloudflare = true;
    }

    // Certificate pinning
    if (
      /CertificatePinner|ssl[_-]?pin|sha256\/|TrustKit|network[_-]?security[_-]?config/i.test(
        content,
      )
    ) {
      if (!result.certPinning) {
        result.certPinning = { detected: true, pins: [], domains: [] };
      }
      const pinMatches = content.matchAll(/sha256\/([A-Za-z0-9+/=]+)/g);
      for (const m of Array.from(pinMatches)) {
        result.certPinning.pins.push(m[1]);
      }
    }

    // Root detection
    if (
      /RootBeer|SafetyNet|isRooted|isDeviceRooted|detectRoot|magisk|superuser/i.test(
        content,
      )
    ) {
      result.rootDetection = true;
    }
  }

  return result;
}

// ─── Secret Decoding Detection ───────────────────────────────────

async function findSecretDecoding(
  fileContents: Map<string, string>,
): Promise<SecretDecodingInfo[]> {
  const results: SecretDecodingInfo[] = [];

  for (const [file, content] of Array.from(fileContents.entries())) {
    // XOR-based decoding
    const xorMatch = content.match(
      /decodeSecret\(\s*(?:get\w+\(\)|"([^"]+)")\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"/,
    );
    if (xorMatch) {
      results.push({
        encodedValue: xorMatch[1] ?? "<from getter>",
        decodingMethod: "Base64 + XOR",
        decodingKey: xorMatch[2],
        file: file.split("/").pop() ?? "",
      });
    }

    // AES usage near secret-ish code
    const aesMatch = content.match(
      /Cipher\.getInstance\(\s*"([^"]+)"\s*\)/,
    );
    if (aesMatch && /decrypt|secret|key/i.test(content)) {
      results.push({
        encodedValue: "<encrypted>",
        decodingMethod: `AES (${aesMatch[1]})`,
        decodingKey: null,
        file: file.split("/").pop() ?? "",
      });
    }
  }

  return results;
}

// ─── Model Analysis ──────────────────────────────────────────────

async function findModels(
  fileContents: Map<string, string>,
  endpointBodyTypes: Set<string>,
): Promise<ModelInfo[]> {
  const models: ModelInfo[] = [];

  for (const [file, content] of Array.from(fileContents.entries())) {
    const fileName = (file.split("/").pop() ?? "").replace(/\.java$|\.kt$/, "");

    // Only models used as request/response bodies, or clearly named as such
    if (!endpointBodyTypes.has(fileName) && !fileName.includes("Request") && !fileName.includes("Response") && !fileName.includes("Filter")) {
      continue;
    }

    if (!content.includes("@SerializedName")) continue;

    const fields: ModelInfo["fields"] = [];
    const fieldMatches = content.matchAll(
      /@SerializedName\(\s*(?:"([^"]+)"|\w+\.\w+)\s*\)\s*(?:@\w+\s*)*(?:private|public|protected)?\s+(?:final\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)/g,
    );
    for (const m of Array.from(fieldMatches)) {
      fields.push({
        serializedName: m[1] ?? m[0],
        type: m[2],
        name: m[3],
      });
    }

    if (fields.length > 0) {
      models.push({ name: fileName, file: file.split("/").pop() ?? "", fields });
    }
  }

  return models;
}

// ─── Main Analysis ───────────────────────────────────────────────

export async function deepAnalyzeApk(outputDir: string): Promise<DeepAnalysisReport> {
  log.info(`Deep analyzing decompiled APK at: ${outputDir}`);

  try {
    await access(outputDir);
  } catch {
    throw new Error(`Directory not found: ${outputDir}`);
  }

  // Detect app type
  let isFlutter = false;
  let isReactNative = false;
  try {
    const manifest = await readFileSafe(join(outputDir, "AndroidManifest.xml"));
    isFlutter = manifest.includes("flutter") || (await findFileExists(outputDir, "libflutter.so"));
    isReactNative = await findFileExists(outputDir, "index.android.bundle");
  } catch { /* ignore */ }

  // Package name
  let packageName = outputDir.split("/").pop() ?? "unknown";
  try {
    const manifest = await readFileSafe(join(outputDir, "AndroidManifest.xml"));
    const pkgMatch = manifest.match(/package="([^"]+)"/);
    if (pkgMatch) packageName = pkgMatch[1];
  } catch { /* ignore */ }

  // Find and read all relevant Java/Kotlin files
  log.info("Scanning source files...");
  const sourcesDir = join(outputDir, "sources");
  const files = await findJavaFiles(sourcesDir);
  log.info(`Found ${files.length} source files to analyze`);

  const fileContents = new Map<string, string>();
  for (const file of files) {
    const content = await readFileSafe(file);
    if (content) fileContents.set(file, content);
  }

  log.info("Analyzing configuration...");
  const configuration = await findConfiguration(files, fileContents);

  log.info("Analyzing authentication...");
  const authentication = await findAuthentication(fileContents);

  log.info("Analyzing interceptor chain...");
  const headers = await findInterceptors(fileContents);

  log.info("Analyzing Retrofit endpoints...");
  const endpoints = await findRetrofitEndpoints(fileContents);

  log.info("Analyzing protection...");
  const protection = await findProtection(fileContents);

  log.info("Analyzing secret decoding...");
  const secretDecoding = await findSecretDecoding(fileContents);

  const bodyTypes = new Set(
    endpoints.map((e) => e.bodyType).filter(Boolean) as string[],
  );
  log.info("Analyzing request/response models...");
  const models = await findModels(fileContents, bodyTypes);

  const report: DeepAnalysisReport = {
    appName: outputDir.split("/").pop() ?? "unknown",
    packageName,
    analyzedAt: new Date().toISOString(),
    isFlutter,
    isReactNative,
    configuration,
    authentication,
    headers,
    endpoints,
    protection,
    models,
    secretDecoding,
  };

  printSummary(report);

  return report;
}

function printSummary(report: DeepAnalysisReport) {
  log.info("─".repeat(50));
  log.info(`App: ${report.appName} (${report.packageName})`);
  log.info(
    `Type: ${report.isFlutter ? "Flutter" : report.isReactNative ? "React Native" : "Native Android"}`,
  );
  log.info(`API Base URL: ${report.configuration.apiBaseUrl ?? "NOT FOUND"}`);
  log.info(`Auth: ${report.authentication.type} | client_id: ${report.authentication.clientId ?? "?"} | api key: ${report.authentication.apiKeyValue ?? "?"}`);
  log.info(`Endpoints: ${report.endpoints.length} | Models: ${report.models.length}`);
  log.info(`Protection: datadome=${!!report.protection.datadome} cloudflare=${report.protection.cloudflare} pinning=${!!report.protection.certPinning} root=${report.protection.rootDetection}`);
  log.info("─".repeat(50));
}

async function findFileExists(dir: string, filename: string): Promise<boolean> {
  async function walk(d: string): Promise<boolean> {
    let entries;
    try {
      entries = await readdir(d, { withFileTypes: true });
    } catch {
      return false;
    }
    for (const entry of entries) {
      if (entry.name === filename) return true;
      if (entry.isDirectory()) {
        if (await walk(join(d, entry.name))) return true;
      }
    }
    return false;
  }
  return walk(dir);
}
