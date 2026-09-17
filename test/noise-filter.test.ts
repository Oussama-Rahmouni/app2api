import { test } from "node:test";
import assert from "node:assert/strict";
import { isNoise } from "../src/apk-analyzer.js";

test("noise filter: known noise domains are filtered", () => {
  assert.equal(isNoise("https://www.googleapis.com/analytics/v1/collect"), true);
  assert.equal(isNoise("https://firebaseinstallations.googleapis.com/v1/projects"), true);
  assert.equal(isNoise("http://www.w3.org/2000/svg"), true);
  assert.equal(isNoise("https://schemas.android.com/apk/res/android"), true);
  assert.equal(isNoise("https://fonts.gstatic.com/s/roboto/font.woff2"), true);
  assert.equal(isNoise("https://app-measurement.com/collect"), true);
  assert.equal(isNoise("http://localhost:8080/debug"), true);
});

test("noise filter: subdomains of noise domains are filtered", () => {
  assert.equal(isNoise("https://deep.link.googleapis.com/v1"), true);
  assert.equal(isNoise("https://my-project.firebaseio.com/users"), true);
});

test("noise filter: real API hosts survive", () => {
  assert.equal(isNoise("https://api.example.com/v1/listings"), false);
  assert.equal(isNoise("https://example.com/mobile/api"), false);
  assert.equal(isNoise("https://staging.internal-api.example.org/health"), false);
});

test("noise filter: unparseable URLs are treated as noise", () => {
  assert.equal(isNoise("not a url at all"), true);
  assert.equal(isNoise(""), true);
});
