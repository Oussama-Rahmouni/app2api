import { test } from "node:test";
import assert from "node:assert/strict";
import { parseVersionOutput } from "../src/tools.js";

test("doctor: parses jadx version", () => {
  assert.equal(parseVersionOutput("jadx", "1.5.1\n"), "1.5.1");
});

test("doctor: parses adb version banner", () => {
  const out = "Android Debug Bridge version 1.0.41\nVersion 35.0.1-11580240\nInstalled as /usr/local/bin/adb\n";
  assert.equal(parseVersionOutput("adb", out), "1.0.41");
});

test("doctor: parses frida version", () => {
  assert.equal(parseVersionOutput("frida", "16.5.2\n"), "16.5.2");
});

test("doctor: parses mitmdump banner", () => {
  const out = "Mitmproxy: 10.4.2 binary\nPython:    3.12.3\nOpenSSL:   OpenSSL 3.2.1\n";
  assert.equal(parseVersionOutput("mitmdump", out), "10.4.2");
});

test("doctor: parses apktool version", () => {
  assert.equal(parseVersionOutput("apktool", "2.10.0\n"), "2.10.0");
});

test("doctor: empty/garbage output yields null or first line", () => {
  assert.equal(parseVersionOutput("jadx", ""), null);
  assert.equal(parseVersionOutput("jadx", "   \n  "), null);
});
