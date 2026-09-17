import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { analyzeApk } from "../src/apk-analyzer.js";

// Tests run compiled from dist-test/test/ — fixtures live in the source tree.
const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "..", "..", "test", "fixtures", "decompiled");

test("pattern extraction: finds endpoints, secrets, keys; filters noise", async () => {
  const report = await analyzeApk(fixtureDir, "example");

  // Package name from the manifest
  assert.equal(report.packageName, "com.example.app");

  // Real URLs survive
  assert.ok(
    report.rawFindings.urls.some((u) => u.startsWith("https://api.example.com")),
    "api.example.com URL should be extracted",
  );

  // Noise URLs filtered
  for (const u of report.rawFindings.urls) {
    assert.ok(!u.includes("googleapis.com"), `noise URL leaked: ${u}`);
    assert.ok(!u.includes("firebaseio.com"), `noise URL leaked: ${u}`);
    assert.ok(!u.includes("w3.org"), `noise URL leaked: ${u}`);
    assert.ok(!u.includes("schemas.android.com"), `noise URL leaked: ${u}`);
  }

  // Base URL extraction
  assert.ok(report.baseUrls.includes("https://api.example.com"));

  // OAuth material
  assert.ok(
    report.authConfig.clientIds.includes("example-android-client"),
    "client_id should be extracted",
  );
  assert.ok(
    report.authConfig.secrets.includes("s3cr3t-value-here"),
    "client_secret should be extracted",
  );

  // OAuth flow assembled
  assert.ok(report.authConfig.oauthFlows.length >= 1);
  const flow = report.authConfig.oauthFlows[0];
  assert.equal(flow.clientId, "example-android-client");

  // Endpoints found (Retrofit paths and smali constants)
  assert.ok(
    report.endpoints.some((e) => e.includes("/api/") || e.includes("/v")),
    `expected endpoint paths, got: ${report.endpoints.join(", ")}`,
  );

  // Custom headers spotted
  assert.ok(
    report.rawFindings.customHeaders.some((h) => h.includes("X-App-Version")),
    "custom header usage should be detected",
  );
});

test("pattern extraction: missing manifest falls back to dir name", async () => {
  const report = await analyzeApk(join(fixtureDir, "sources"), "fallbackname");
  assert.equal(report.packageName, "fallbackname");
});
