import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { runPipeline } from "../src/pipeline.js";

// Tests run compiled from dist-test/test/ — fixtures live in the source tree.
const here = dirname(fileURLToPath(import.meta.url));
const fixtureDir = join(here, "..", "..", "test", "fixtures", "decompiled");

test("pipeline: directory input runs the full static chain with zero external tools", async () => {
  const out = await mkdtemp(join(tmpdir(), "app2api-test-"));

  const result = await runPipeline(fixtureDir, { outputDir: out, workDir: join(out, "work") });

  // Framework detection ran
  assert.equal(result.framework.framework, "java-kotlin");

  // Spec was generated with real content
  const spec = result.spec;
  assert.equal(spec.packageName, "com.example.app");
  assert.equal(spec.baseUrl, "https://api.example.com");
  assert.equal(spec.authentication.type, "oauth2");
  assert.equal(spec.authentication.clientId, "example-android-client");
  assert.equal(spec.authentication.tokenUrl, "https://api.example.com/oauth/token");
  assert.ok(spec.endpoints.length >= 3, `expected >= 3 endpoints, got ${spec.endpoints.length}`);
  assert.equal(spec.headers["X-App-Version"], "3.2.1");
  assert.equal(spec.protection.certPinning, true);
  assert.equal(spec.crawlerHints.paginationMethod, "cursor");

  // SDK keys from strings.xml
  assert.equal(spec.sdkKeys.firebaseProjectId, "example-app-12345");
  assert.equal(spec.sdkKeys.facebookAppId, "123456789012345");

  // Security posture
  assert.equal(spec.security.cleartextAllowed, true); // manifest usesCleartextTraffic
  assert.deepEqual(spec.security.pinnedDomains, ["api.example.com"]);

  // Output files written
  const specFile = JSON.parse(await readFile(join(result.outDir, "api-spec.json"), "utf-8"));
  assert.equal(specFile.packageName, "com.example.app");

  const reportMd = await readFile(join(result.outDir, "report.md"), "utf-8");
  assert.match(reportMd, /# API Surface Report: /);
  assert.match(reportMd, /## Authentication/);
  assert.match(reportMd, /## Endpoints/);

  const intelFile = JSON.parse(await readFile(join(result.outDir, "intel.json"), "utf-8"));
  assert.equal(intelFile.packageName, "com.example.app");

  const deepFile = JSON.parse(await readFile(join(result.outDir, "deep-analysis.json"), "utf-8"));
  assert.ok(Array.isArray(deepFile.endpoints));
});
