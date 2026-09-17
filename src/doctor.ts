/**
 * doctor — probe external tools and report what's installed.
 */

import { probeAllTools, type ToolProbe } from "./tools.js";

export function formatDoctorReport(probes: ToolProbe[]): string {
  const lines: string[] = [];
  lines.push("app2api doctor — external tool check");
  lines.push("");

  const width = Math.max(...probes.map((p) => p.name.length));

  for (const p of probes) {
    const name = p.name.padEnd(width);
    if (p.installed) {
      lines.push(`  ok       ${name}  ${p.version ?? "version unknown"}`);
    } else {
      lines.push(`  MISSING  ${name}  ${p.purpose}`);
      lines.push(`           ${" ".padEnd(width)}  install: ${p.installHint}`);
    }
  }

  lines.push("");
  lines.push("Notes:");
  lines.push("  - Static analysis of an already-decompiled directory needs no tools.");
  lines.push("  - APK input needs: jadx (or decompile yourself and pass the directory).");
  lines.push("  - Dynamic mode needs: adb + frida + mitmdump, plus frida-server on the device.");

  const missing = probes.filter((p) => !p.installed);
  lines.push("");
  lines.push(missing.length === 0
    ? "All tools installed."
    : `${missing.length} tool(s) missing — see hints above.`);

  return lines.join("\n");
}

export function runDoctor(): string {
  return formatDoctorReport(probeAllTools());
}
