import { test } from "node:test";
import assert from "node:assert/strict";
import { parseArgs } from "../src/cli.js";

test("parseArgs: key-value pairs", () => {
  const args = parseArgs(["--apk", "example.apk", "--domain", "api.example.com"]);
  assert.equal(args["apk"], "example.apk");
  assert.equal(args["domain"], "api.example.com");
});

test("parseArgs: bare flags become true", () => {
  const args = parseArgs(["--reflutter", "--apk", "example.apk"]);
  assert.equal(args["reflutter"], true);
  assert.equal(args["apk"], "example.apk");
});

test("parseArgs: --no- prefix becomes false", () => {
  const args = parseArgs(["--no-mitm", "--no-ssl", "--apk", "example.apk"]);
  assert.equal(args["mitm"], false);
  assert.equal(args["ssl"], false);
  assert.equal(args["apk"], "example.apk");
});

test("parseArgs: flag followed by another flag is boolean, not a value", () => {
  const args = parseArgs(["--keep", "--min-length", "12"]);
  assert.equal(args["keep"], true);
  assert.equal(args["min-length"], "12");
});

test("parseArgs: positional args are ignored", () => {
  const args = parseArgs(["example.apk", "--output", "out/"]);
  assert.equal(args["output"], "out/");
  assert.equal(Object.keys(args).length, 1);
});

test("parseArgs: empty input", () => {
  assert.deepEqual(parseArgs([]), {});
});
