import { test } from "node:test";
import assert from "node:assert/strict";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { detectFrameworkInDir } from "../src/framework-detector.js";

// Tests run compiled from dist-test/test/ — fixtures live in the source tree.
const here = dirname(fileURLToPath(import.meta.url));
const fw = (name: string) => join(here, "..", "..", "test", "fixtures", "frameworks", name);

test("detects flutter from libapp.so + libflutter.so", async () => {
  const report = await detectFrameworkInDir(fw("flutter"));
  assert.equal(report.framework, "flutter");
  assert.equal(report.difficulty, "hard");
  assert.match(report.codeLocation, /libapp\.so/);
});

test("detects react-native from index.android.bundle", async () => {
  const report = await detectFrameworkInDir(fw("rn"));
  assert.equal(report.framework, "react-native");
  assert.equal(report.difficulty, "easy");
});

test("detects cordova from assets/www", async () => {
  const report = await detectFrameworkInDir(fw("cordova"));
  assert.equal(report.framework, "cordova");
  assert.equal(report.difficulty, "trivial");
});

test("detects xamarin from assemblies dir", async () => {
  const report = await detectFrameworkInDir(fw("xamarin"));
  assert.equal(report.framework, "xamarin");
  assert.equal(report.difficulty, "medium");
});

test("detects unity-il2cpp from libil2cpp.so", async () => {
  const report = await detectFrameworkInDir(fw("unity-il2cpp"));
  assert.equal(report.framework, "unity-il2cpp");
  assert.equal(report.difficulty, "hard");
});

test("falls back to java-kotlin when no markers exist", async () => {
  const report = await detectFrameworkInDir(fw("native"));
  assert.equal(report.framework, "java-kotlin");
  assert.equal(report.difficulty, "easy");
  assert.equal(report.tool, "jadx");
});
