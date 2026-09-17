# app2api

APK in, API spec out.

Point it at an Android APK (or an already-decompiled directory) and it extracts the app's API surface: endpoints, the auth scheme (OAuth client_id/secret, API keys, bearer), static headers, third-party SDK keys, and security config (cert pinning, cleartext). An optional dynamic mode captures the live traffic with Frida + mitmproxy on a rooted device.

Output: a machine-readable `api-spec.json` plus a human `report.md`.

## Why

Mobile APIs are usually the least-defended surface of a service. The web frontend gets rate limits, bot management, and cookie churn. The app talks to the same data over an OkHttp client whose TLS fingerprint is whitelisted, authenticates with OAuth instead of cookies, and — because apps are built for features, not anti-scraping — ships its endpoints, keys, and header contract in plaintext inside the binary. Reversing the APK is faster than fighting the website's defenses, and the resulting spec is more stable.

## Install

```sh
npm install
npm run build
npm link        # puts `app2api` on PATH
```

Node ≥ 20. Zero runtime npm dependencies — external tools are shell-outs (see the table below).

Supply your own APK. This tool does not download apps. Get one from a device you own:

```sh
adb shell pm path com.example.app       # find the APK path on the device
adb pull /data/app/.../base.apk example.apk
```

or use [apkeep](https://github.com/EFForg/apkeep).

## Quickstart

```sh
app2api doctor                  # check your toolchain first
app2api analyze example.apk     # full static pipeline
```

`analyze` writes `output/example/`:

```
api-spec.json       machine-readable API spec
report.md           human report
deep-analysis.json  raw deep analysis (endpoints, interceptors, models)
intel.json          SDK keys / infra / security intel
```

What the spec looks like (illustrative, truncated):

```json
{
  "appName": "example",
  "packageName": "com.example.app",
  "framework": "java-kotlin",
  "baseUrl": "https://api.example.com",
  "authentication": {
    "type": "oauth2",
    "clientId": "example-android-client",
    "tokenUrl": "https://api.example.com/oauth/token",
    "grantTypes": ["password"]
  },
  "headers": { "X-App-Version": "3.2.1", "X-Platform": "android" },
  "userAgent": "ExampleApp/%s (Android %s; %s)",
  "endpoints": [
    { "method": "GET", "path": "/v1/listings",
      "fullUrl": "https://api.example.com/v1/listings",
      "authenticated": true },
    { "method": "POST", "path": "/v1/auth/login",
      "fullUrl": "https://api.example.com/v1/auth/login",
      "authenticated": false, "bodyType": "LoginRequest" }
  ],
  "protection": { "certPinning": true, "rootDetection": false, "...": "..." },
  "crawlerHints": { "searchEndpoint": "/v1/search", "paginationMethod": "cursor" }
}
```

Already decompiled the APK yourself? Skip jadx entirely — static analysis of a directory needs zero external tools:

```sh
app2api analyze ./jadx-output/example/
```

## Subcommands

| Command | What it does |
|---|---|
| `app2api analyze <apk-or-dir>` | Full static pipeline: framework detect → decompile (if APK) → extract → `api-spec.json` + `report.md` |
| `app2api detect <apk-or-dir>` | Framework detection only (java-kotlin / react-native / flutter / cordova / xamarin / unity) with difficulty rating |
| `app2api flutter <apk>` | Flutter `libapp.so` string/structure extraction (`--reflutter` for deeper snapshot recovery) |
| `app2api dynamic --apk <apk> --domain <d>` | Live capture: Frida hooks + mitmproxy on a rooted device (`--list-devices`, `--time 120`, `--no-mitm`, `--no-ssl`) |
| `app2api doctor` | Probe external tools, show versions and install hints |

## External tools

None required for analyzing an already-decompiled directory. Otherwise:

| Tool | Needed for | Install |
|---|---|---|
| jadx | `analyze` on an APK file | [github.com/skylot/jadx](https://github.com/skylot/jadx) |
| unzip | APK/XAPK extraction | preinstalled on most systems |
| strings | Flutter `libapp.so` extraction | binutils |
| adb | dynamic mode | Android platform-tools |
| frida | dynamic mode | `pip install frida-tools` |
| mitmdump | dynamic mode | `pip install mitmproxy` |
| reFlutter | optional deep Flutter recovery | `pip install reflutter` |

Each tool is probed at runtime (`--version`) and missing tools produce an install hint, not a stack trace. `app2api doctor` shows the full matrix.

## How it works

```
            ┌─────────────────────────────────────────────────┐
 APK/dir →  │ detect framework (RN? Flutter? Cordova? Unity?) │
            └───────────────┬─────────────────────────────────┘
                            │ APK → jadx (dir → skip)
                            ▼
            ┌─────────────────────────────────────────────────┐
            │ pattern pass   URLs, OAuth pairs, API keys,     │
            │                header names — noise filtered    │
            ├─────────────────────────────────────────────────┤
            │ deep pass      config classes, Retrofit         │
            │                interfaces, OkHttp interceptor   │
            │                chain, secret decoding, WAF SDKs │
            ├─────────────────────────────────────────────────┤
            │ intel pass     SDK keys (Firebase/Stripe/...),  │
            │                staging/admin/CDN URLs, manifest │
            │                flags, network security config,  │
            │                deep links, feature flags        │
            └───────────────┬─────────────────────────────────┘
                            ▼
              api-spec.json + report.md (+ raw JSON)

 dynamic mode (optional, rooted device):
   adb install → frida-server → attach frida
     (cert unpinning + OkHttp network interceptor + native SSL_read/write)
   + mitmdump parallel capture layer
   → dedup → endpoints, auth headers, common headers
```

## Dynamic mode requirements

- A rooted emulator (e.g. Android emulator with a `-writable-system` AVD, no Play Services image) or a rooted device.
- frida-server pushed and running on the device (`--frida-server <path>` pushes it for you).
- The mitmproxy CA installed as a system cert on the device for HTTPS capture of non-hooked traffic.
- Then: `app2api dynamic --apk example.apk --domain api.example.com --time 120` and use the app while it captures.

## Scope and ethics

Analyze apps you are authorized to analyze: your own apps, apps you're paid to audit, security research within the program's rules, interoperability work. Extracting an API surface is a normal reverse-engineering activity in those contexts. Don't use it to abuse services you have no right to access, and respect the law where you are.

## Limitations

- Heavily obfuscated or native-only apps (logic in a custom `.so`) defeat static analysis — use dynamic mode.
- Flutter: string extraction from `libapp.so` recovers URLs, endpoints, and keys, but not call graphs. Real symbol recovery needs reFlutter (`--reflutter`), and even that degrades on obfuscated builds.
- Dynamic mode needs a rooted device or emulator; there is no way around that for cert-pinned apps.
- Secrets decoded at runtime (XOR/AES in native code) are flagged with their decoding method, not decoded for you — read the indicated class.

## License

MIT — Oussama Rahmouni
