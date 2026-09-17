import { test } from "node:test";
import assert from "node:assert/strict";
import { generateSpec, type ApiSpec } from "../src/pipeline.js";
import type { ApkReport } from "../src/types.js";
import type { DeepAnalysisReport } from "../src/apk-deep-analyzer.js";
import type { IntelReport } from "../src/apk-intel-extractor.js";

const basic: ApkReport = {
  appName: "example",
  packageName: "com.example.app",
  analyzedAt: "2026-01-01T00:00:00.000Z",
  isFlutter: false,
  baseUrls: ["https://api.example.com"],
  endpoints: ["/v1/listings", "/v1/auth/login"],
  authConfig: {
    clientIds: ["example-android-client"],
    secrets: ["s3cr3t"],
    apiKeys: [],
    oauthFlows: [
      { tokenUrl: "https://api.example.com/oauth/token", grantType: "password", clientId: "example-android-client" },
    ],
  },
  headers: {},
  rawFindings: { urls: [], authTokens: [], apiEndpoints: [], customHeaders: [] },
};

const deep: DeepAnalysisReport = {
  appName: "example",
  packageName: "com.example.app",
  analyzedAt: "2026-01-01T00:00:00.000Z",
  isFlutter: false,
  isReactNative: false,
  configuration: {
    apiBaseUrl: "https://api.example.com",
    otherUrls: {},
    configClass: "ApiConfig.java",
  },
  authentication: {
    type: "oauth2",
    clientId: "example-android-client",
    clientSecret: null,
    clientSecretEncoded: "ZW5jb2RlZA==",
    secretDecodingMethod: "decodeXor",
    tokenUrl: "/oauth/token",
    grantTypes: ["password"],
    apiKeyHeader: null,
    apiKeyValue: null,
  },
  headers: {
    interceptorChain: [
      { name: "authInterceptor", type: "application", file: "NetworkModule.java", headersAdded: [], description: "" },
    ],
    staticHeaders: { "X-App-Version": "3.2.1", Authorization: "<dynamic>" },
    userAgentFormat: "ExampleApp/%s (Android %s; %s)",
  },
  endpoints: [
    { method: "GET", path: "/v1/listings", authenticated: true, headers: {}, bodyType: null, returnType: "ListingResponse", file: "ApiService.java" },
    { method: "POST", path: "/v1/auth/login", authenticated: false, headers: {}, bodyType: "LoginRequest", returnType: "TokenResponse", file: "ApiService.java" },
    { method: "GET", path: "/v1/search", authenticated: true, headers: { "X-Api-Key": "<parameter>" }, bodyType: null, returnType: "SearchResponse", file: "ApiService.java" },
  ],
  protection: {
    datadome: null,
    cloudflare: false,
    certPinning: { detected: true, pins: ["AAAA"], domains: ["api.example.com"] },
    rootDetection: true,
  },
  models: [
    {
      name: "ListingResponse",
      file: "ListingResponse.java",
      fields: [
        { name: "id", serializedName: "id", type: "String" },
        { name: "title", serializedName: "title", type: "String" },
        { name: "cursor", serializedName: "cursor", type: "String" },
      ],
    },
  ],
  secretDecoding: [],
};

const intel: IntelReport = {
  appName: "example",
  packageName: "com.example.app",
  analyzedAt: "2026-01-01T00:00:00.000Z",
  sdkKeys: {
    google: { mapsApiKey: "AIzaDUMMY", appId: null, clientId: null, crashReportingKey: null },
    firebase: { databaseUrl: null, storageBucket: null, projectId: "example-app-12345", senderId: null },
    facebook: { appId: "123456789012345", clientToken: null },
    sentry: { dsn: null },
    stripe: { publishableKey: null, secretKey: null },
    analytics: [],
    other: [],
  },
  infrastructure: { allUrls: [], awsResources: [], gcpResources: [], stagingUrls: [], adminUrls: [], cmsEndpoints: [], cdnDomains: [] },
  security: {
    networkConfig: { cleartextAllowed: false, certPinning: true, pinnedDomains: ["api.example.com"], debugOverrides: false, trustAnchors: [] },
    manifest: {
      allowBackup: true,
      debuggable: false,
      cleartextTraffic: true,
      exportedComponents: [{ name: ".MainActivity", type: "activity", intentFilters: ["android.intent.action.VIEW"] }],
      permissions: ["android.permission.INTERNET"],
      deepLinks: [],
    },
    webviewIssues: [],
    sqlInjection: [],
  },
  storage: { sharedPrefsKeys: [], databases: [], allModels: [] },
  buildInfo: { applicationId: null, versionName: "3.2.1", versionCode: "30201", buildType: null, isDebug: false, customFields: {}, targetSdk: null, minSdk: null },
  deepLinks: [],
  featureFlags: [],
};

test("generateSpec shapes a complete ApiSpec", () => {
  const spec = generateSpec(basic, deep, intel, "java-kotlin");

  // Top level
  assert.equal(spec.appName, "example");
  assert.equal(spec.packageName, "com.example.app");
  assert.equal(spec.framework, "java-kotlin");
  assert.equal(spec.baseUrl, "https://api.example.com");

  // Authentication block
  assert.equal(spec.authentication.type, "oauth2");
  assert.equal(spec.authentication.clientId, "example-android-client");
  assert.equal(spec.authentication.tokenUrl, "https://api.example.com/oauth/token");
  assert.deepEqual(spec.authentication.grantTypes, ["password"]);
  assert.equal(spec.authentication.oauthFlows.length, 1);

  // Headers: dynamic placeholders dropped, static kept
  assert.equal(spec.headers["X-App-Version"], "3.2.1");
  assert.ok(!("Authorization" in spec.headers));
  assert.equal(spec.userAgent, "ExampleApp/%s (Android %s; %s)");

  // Endpoints array
  assert.equal(spec.endpoints.length, 3);
  const login = spec.endpoints.find((e) => e.path === "/v1/auth/login")!;
  assert.equal(login.method, "POST");
  assert.equal(login.fullUrl, "https://api.example.com/v1/auth/login");
  assert.equal(login.authenticated, false);
  assert.equal(login.bodyType, "LoginRequest");

  // Protection merged from deep + intel
  assert.equal(spec.protection.certPinning, true);
  assert.equal(spec.protection.rootDetection, true);
  assert.equal(spec.protection.datadome, false);

  // SDK keys
  assert.equal(spec.sdkKeys.googleMapsApiKey, "AIzaDUMMY");
  assert.equal(spec.sdkKeys.firebaseProjectId, "example-app-12345");
  assert.equal(spec.sdkKeys.stripeSecretKeyFound, false);

  // Security posture
  assert.equal(spec.security.cleartextAllowed, true); // manifest flag wins
  assert.equal(spec.security.exportedComponents, 1);

  // Crawler hints: search endpoint + cursor pagination from models
  assert.equal(spec.crawlerHints.searchEndpoint, "/v1/search");
  assert.equal(spec.crawlerHints.paginationMethod, "cursor");
  assert.ok(spec.crawlerHints.listingFields.includes("cursor"));
});

test("generateSpec tolerates empty reports", () => {
  const emptyDeep: DeepAnalysisReport = {
    ...deep,
    configuration: { apiBaseUrl: null, otherUrls: {}, configClass: null },
    authentication: {
      type: "none", clientId: null, clientSecret: null, clientSecretEncoded: null,
      secretDecodingMethod: null, tokenUrl: null, grantTypes: [], apiKeyHeader: null, apiKeyValue: null,
    },
    headers: { interceptorChain: [], staticHeaders: {}, userAgentFormat: null },
    endpoints: [],
    protection: { datadome: null, cloudflare: false, certPinning: null, rootDetection: false },
    models: [],
  };
  const emptyBasic: ApkReport = { ...basic, baseUrls: [], authConfig: { clientIds: [], secrets: [], apiKeys: [], oauthFlows: [] } };

  const spec: ApiSpec = generateSpec(emptyBasic, emptyDeep, intel, "unknown");
  assert.equal(spec.baseUrl, null);
  assert.equal(spec.authentication.type, "none");
  assert.equal(spec.authentication.tokenUrl, null);
  assert.deepEqual(spec.endpoints, []);
  assert.equal(spec.crawlerHints.searchEndpoint, null);
});
