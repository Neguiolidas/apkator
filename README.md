# Apkator

Android APK security analysis. Two modes, one tool.

- **Web UI** — runs on localhost, powered by your backend. Drop an APK in the browser and get the full analysis (deep scan, vulnerabilities, suggestions) without touching the terminal.
- **CLI deep scan** — full static analysis with apktool: data flows, vulnerability patterns, hardcoded secrets, trackers, permission over-declaration, and actionable fix suggestions.

## Quick start

### Web (localhost)

```bash
git clone https://github.com/Neguiolidas/apkator
cd apkator
node web/server.js
# open http://localhost:8735
```

### CLI

Requires Node 18+ and Java (for apktool).

```bash
git clone https://github.com/Neguiolidas/apkator
cd apkator
node bin/apkator.js app.apk --deep
```

## CLI usage

```bash
node bin/apkator.js app.apk              # fast scan
node bin/apkator.js app.apk --deep       # full smali analysis
node bin/apkator.js app.apk --deep --show=code      # vulnerability details
node bin/apkator.js app.apk --deep --show=network    # domains + data flows
node bin/apkator.js app.apk --deep --show=all        # everything
node bin/apkator.js app.apk --deep --json            # machine-readable
node bin/apkator.js --init               # configure AI provider for --explain
node bin/apkator.js --help
```

## What it detects

**Manifest:** debuggable, allowBackup, cleartext traffic, exported components, taskAffinity hijacking, deep links without autoVerify, unprotected content providers, missing networkSecurityConfig.

**Permissions:** 24 known permissions classified (critical/warning/info), over-declaration detection (declared but unused in code), category anomaly detection.

**Code (deep):** MD5/SHA-1/DES/ECB crypto issues, WebView JS bridge, SSL hostname verification bypass, custom TrustManager, raw SQL, insecure Random, world-readable/writable files, IMEI/IMSI access, hardcoded crypto keys/IVs, dynamic code loading, shell exec, hardcoded API keys (OpenAI, Google, AWS, GitHub, Slack).

**Network:** domains extracted from code and resources, permission-to-domain data flows with confidence levels, tracker SDK detection.

## Architecture

```
bin/apkator.js   CLI entry point
lib/
  config.js       AI provider config (~/.config/apkator/config.json)
  suggest.js      deterministic fix suggestions per finding
  narrate.js      AI narrative or deterministic fallback
  flows.json      permission -> API signatures for data flow detection
  baselines.json  per-category permission baselines for anomaly detection
web/
  server.js       local server (node web/server.js, port 8735)
  public/         web UI (upload, results, AI provider config)
```

Decode cache lives in `~/.cache/apkator/decode`, keyed by SHA256 + mode (fast/deep).

## Privacy

The web UI runs on your localhost. APKs are analyzed by your own backend — nothing is sent to any third party. The AI provider config (optional) calls only the endpoint you configure.

## License

MIT
