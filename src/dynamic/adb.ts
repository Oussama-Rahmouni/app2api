/**
 * Minimal adb wrapper — just what the dynamic pipeline needs.
 * Shells out to the `adb` binary; no npm dependencies.
 */

import { execSync, spawnSync } from "node:child_process";
import { createLogger } from "../logger.js";
import { requireTool, TOOLS } from "../tools.js";

const log = createLogger("adb");

export interface AdbDevice {
  serial: string;
  state: string;
  model?: string;
}

const ADB_HINT = TOOLS.find((t) => t.name === "adb")!.installHint;

function adb(args: string[], serial?: string, timeout = 30_000): string {
  const full = serial ? ["-s", serial, ...args] : args;
  return execSync(`adb ${full.map((a) => `"${a}"`).join(" ")}`, {
    encoding: "utf-8",
    timeout,
    maxBuffer: 10 * 1024 * 1024,
  }).trim();
}

export class ADB {
  constructor(public readonly serial?: string) {}

  static listDevices(): AdbDevice[] {
    requireTool("adb", ADB_HINT);
    const out = adb(["devices", "-l"]);
    return out
      .split("\n")
      .slice(1)
      .map((l) => l.trim())
      .filter((l) => l.length > 0 && !l.startsWith("*"))
      .map((l) => {
        const [serial, state, ...rest] = l.split(/\s+/);
        const modelField = rest.find((r) => r.startsWith("model:"));
        return { serial, state, model: modelField?.slice(6) };
      })
      .filter((d) => d.state === "device");
  }

  /** First connected device, or throw with a clear message. */
  static firstAvailable(): ADB {
    const devices = ADB.listDevices();
    if (devices.length === 0) {
      throw new Error(
        "No adb devices found. Connect a rooted device/emulator and check `adb devices`.",
      );
    }
    log.info(`Using device: ${devices[0].serial} (${devices[0].model ?? "unknown model"})`);
    return new ADB(devices[0].serial);
  }

  shell(cmd: string): string {
    return adb(["shell", cmd], this.serial);
  }

  getDeviceModel(): string {
    return this.shell("getprop ro.product.model");
  }

  getAndroidVersion(): string {
    return this.shell("getprop ro.build.version.release");
  }

  getArchitecture(): string {
    return this.shell("getprop ro.product.cpu.abi");
  }

  installApk(apkPath: string): void {
    log.info(`Installing ${apkPath}...`);
    adb(["install", "-r", "-g", apkPath], this.serial, 180_000);
  }

  /** Package name from an APK via aapt (bundled with Android build-tools). */
  getPackageNameFromApk(apkPath: string): string {
    const out = execSync(`aapt dump badging "${apkPath}" 2>/dev/null | head -1`, {
      encoding: "utf-8",
      timeout: 30_000,
    });
    const match = out.match(/package: name='([^']+)'/);
    if (!match) throw new Error(`Could not parse package name from ${apkPath}`);
    return match[1];
  }

  startApp(packageName: string): void {
    this.shell(`monkey -p ${packageName} -c android.intent.category.LAUNCHER 1`);
  }

  stopApp(packageName: string): void {
    try {
      this.shell(`am force-stop ${packageName}`);
    } catch { /* app may not be running */ }
  }

  /** Route device traffic through a proxy on the host (via adb reverse). */
  setProxy(host: string, port: number): void {
    this.shell(`settings put global http_proxy ${host}:${port}`);
  }

  clearProxy(): void {
    this.shell("settings put global http_proxy :0");
  }

  /** device:port → host:port */
  reversePort(port: number): void {
    adb(["reverse", `tcp:${port}`, `tcp:${port}`], this.serial);
  }

  removeReverse(port: number): void {
    try {
      adb(["reverse", "--remove", `tcp:${port}`], this.serial);
    } catch { /* ignore */ }
  }

  isFridaServerRunning(): boolean {
    try {
      const out = this.shell("pidof frida-server");
      return out.length > 0;
    } catch {
      return false;
    }
  }

  /**
   * Start frida-server pushed to /data/local/tmp. Requires root
   * (rooted emulator or Magisk). Backgrounded via su.
   */
  startFridaServer(): void {
    log.info("Starting frida-server (requires root)...");
    const result = spawnSync(
      "adb",
      [...(this.serial ? ["-s", this.serial] : []), "shell",
        "su -c '/data/local/tmp/frida-server -D'"],
      { encoding: "utf-8", timeout: 10_000 },
    );
    if (result.status !== 0) {
      throw new Error(
        "Failed to start frida-server. Push it first:\n" +
        "  adb push frida-server /data/local/tmp/ && adb shell \"chmod 755 /data/local/tmp/frida-server\"\n" +
        "or pass --frida-server <path> to push it automatically.",
      );
    }
  }

  /** Push and start a frida-server binary from the host. */
  setupFridaServer(hostPath: string): void {
    adb(["push", hostPath, "/data/local/tmp/frida-server"], this.serial, 60_000);
    this.shell("chmod 755 /data/local/tmp/frida-server");
    this.startFridaServer();
  }

  /** Poll `pidof` until the process appears. */
  waitForProcess(packageName: string, timeoutMs: number): { name: string; pid: number } {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      try {
        const out = this.shell(`pidof ${packageName}`);
        const pid = parseInt(out, 10);
        if (pid > 0) return { name: packageName, pid };
      } catch { /* not up yet */ }
      spawnSync("sleep", ["0.5"]);
    }
    throw new Error(`Process ${packageName} did not start within ${timeoutMs / 1000}s`);
  }
}
