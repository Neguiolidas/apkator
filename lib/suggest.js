// Deterministic suggestion engine: finding -> actionable fix + detailed explanation
const SUGGESTIONS = {
  'Debuggable enabled': {
    fix: 'Set android:debuggable="false" in AndroidManifest.xml or remove the attribute (defaults to false).',
    priority: 'high',
    detail: 'When debuggable is true, anyone with ADB access can attach a debugger, dump memory, read variables at runtime, and bypass root checks. Tools like Frida and Objection rely on this flag. Release builds must never ship with it enabled.',
  },
  'Backup allowed': {
    fix: 'Set android:allowBackup="false" or implement BackupAgent with encrypted backup.',
    priority: 'medium',
    detail: 'With allowBackup=true, an attacker with USB access can run "adb backup" and extract the app private data directory, including databases, shared preferences, tokens, and cached credentials, without root.',
  },
  'Cleartext traffic allowed': {
    fix: 'Set android:usesCleartextTraffic="false" and use HTTPS everywhere. Add networkSecurityConfig for exceptions.',
    priority: 'high',
    detail: 'Cleartext (HTTP) traffic can be intercepted and modified by anyone on the network path (MITM). Credentials, tokens, and personal data sent over HTTP are readable in plain text. This also fails Play Store security review for sensitive apps.',
  },
  'Weak crypto: AES/ECB': {
    fix: 'Migrate to AES/GCM/NoPadding. ECB leaks data patterns.',
    priority: 'medium',
    detail: 'ECB mode encrypts each block independently, so identical plaintext blocks produce identical ciphertext. An attacker observing ciphertext can detect repeated patterns (e.g. the classic ECB penguin). GCM adds authentication and a unique nonce per encryption.',
  },
  'MD5 hash usage (broken)': {
    fix: 'Replace MD5 with SHA-256 or SHA-3. MD5 is broken for collision resistance.',
    priority: 'medium',
    detail: 'MD5 collisions can be generated in seconds on commodity hardware. If used for integrity checks or signatures, an attacker can craft a different payload with the same hash. It is also too fast for password hashing (use bcrypt/argon2).',
  },
  'SHA-1 hash usage (weak)': {
    fix: 'Replace SHA-1 with SHA-256. SHA-1 is deprecated for security use.',
    priority: 'low',
    detail: 'SHA-1 collision attacks are practical (SHAttered, 2017). Browsers and CAs deprecated it years ago. Migrate to SHA-256 for any integrity or signature purpose.',
  },
  'DES encryption (broken)': {
    fix: 'Replace DES with AES-256/GCM. DES 56-bit keys are brute-forceable.',
    priority: 'high',
    detail: 'DES uses 56-bit effective keys, brute-forceable in under a day with modern hardware (COPACOBANA did it in ~13 hours back in 2008). Any data "protected" by DES is effectively plaintext to a motivated attacker.',
  },
  'ECB cipher mode (leaks patterns)': {
    fix: 'Use AES/GCM/NoPadding instead of ECB. ECB reveals plaintext patterns.',
    priority: 'medium',
    detail: 'ECB encrypts each block independently with the same key. Identical plaintext blocks yield identical ciphertext, leaking structure. The fix is an authenticated mode with a random IV per message: AES/GCM/NoPadding.',
  },
  'WebView JS bridge (XSS risk)': {
    fix: 'Audit addJavascriptInterface: expose minimal API, validate all input, require API 17+.',
    priority: 'medium',
    detail: 'addJavascriptInterface exposes Java methods to JavaScript running in the WebView. If the WebView loads untrusted content (ads, user HTML, HTTP pages), injected JS can call those methods. Before API 17, reflection allowed full RCE. Expose the smallest surface possible and validate every argument.',
  },
  'WebView file access enabled': {
    fix: 'Set setAllowFileAccess(false) unless loading local files. Prevents file theft via WebView.',
    priority: 'medium',
    detail: 'With file access enabled, a malicious page loaded in the WebView can use file:// URLs or XHR to read local files the app can access, then exfiltrate them. Disable unless the WebView genuinely needs local file loading.',
  },
  'SSL hostname verification disabled': {
    fix: 'Remove ALLOW_ALL_HOSTNAME_VERIFIER. Use default verifier or pin certificates.',
    priority: 'high',
    detail: 'Disabling hostname verification means the app accepts any valid certificate for any domain. An attacker with any CA-signed cert (or a compromised CA) can MITM all TLS traffic. This is one of the most common Play Store rejection reasons.',
  },
  'Custom TrustManager (MITM risk)': {
    fix: 'Audit checkServerTrusted: ensure it validates the chain. Empty implementations allow MITM.',
    priority: 'medium',
    detail: 'A custom TrustManager whose checkServerTrusted does nothing (or only logs) accepts any certificate, including self-signed attacker certs. If pinning is intended, verify the public key hash explicitly; otherwise delegate to the default trust manager.',
  },
  'Raw SQL query (injection risk)': {
    fix: 'Use parameterized queries (?, bindArgs) instead of string concatenation in rawQuery.',
    priority: 'low',
    detail: 'rawQuery with string-built SQL is injectable if any part comes from user input, intents, or network. Parameterized queries separate code from data. Even local-only databases matter: malicious apps can sometimes influence inputs via exported components.',
  },
  'Insecure Random (not SecureRandom)': {
    fix: 'Use java.security.SecureRandom for tokens, keys, or session IDs.',
    priority: 'low',
    detail: 'java.util.Random is a predictable LCG. If used for session tokens, password reset codes, or IVs, an attacker who observes outputs can predict future values. SecureRandom uses OS entropy.',
  },
  'World-readable file mode': {
    fix: 'Replace MODE_WORLD_READABLE with MODE_PRIVATE. World-readable exposes data to all apps.',
    priority: 'medium',
    detail: 'MODE_WORLD_READABLE (deprecated since API 17) lets any app on the device read the file. SharedPreferences or caches with tokens become readable by malware with zero permissions.',
  },
  'World-writable file mode': {
    fix: 'Replace MODE_WORLD_WRITEABLE with MODE_PRIVATE. World-writable allows tampering.',
    priority: 'high',
    detail: 'MODE_WORLD_WRITEABLE lets any app modify the file. An attacker can overwrite configs, inject malicious data, or replace DEX/plugin files the app later loads, leading to code execution.',
  },
  'Custom taskAffinity (task hijacking risk)': {
    fix: 'Set android:taskAffinity="" or remove it. Custom affinity allows task hijacking overlays.',
    priority: 'low',
    detail: 'Activities with the same taskAffinity can be placed in the same task. A malicious app declaring the same affinity can overlay its activity on top of yours (tapjacking / credential phishing). Empty affinity isolates the task.',
  },
  'No networkSecurityConfig (no cert pinning)': {
    fix: 'Add android:networkSecurityConfig with certificate pinning for critical domains.',
    priority: 'low',
    detail: 'Without a network security config there is no certificate pinning and cleartext policy is permissive by default on older targets. Pinning the expected public keys makes MITM with a rogue CA-signed cert fail closed.',
  },
  'IMEI access (persistent identifier)': {
    fix: 'Avoid getDeviceId(). Use Advertising ID or app-scoped identifiers (Play policy restricts IMEI).',
    priority: 'medium',
    detail: 'IMEI is a permanent hardware identifier that cannot be reset. Collecting it enables cross-app tracking and violates Play Store policy (requires prominent disclosure and is restricted to device-owner use cases). Use the Advertising ID (resettable) or Firebase Installation ID.',
  },
  'IMSI access (persistent identifier)': {
    fix: 'Avoid getSubscriberId(). Use non-persistent identifiers.',
    priority: 'medium',
    detail: 'IMSI identifies the SIM/subscriber permanently. Same tracking and policy concerns as IMEI. Rarely justified in app code.',
  },
  'Debug logging in release (info leak)': {
    fix: 'Remove Log.d calls or guard with BuildConfig.DEBUG. Logs leak via logcat.',
    priority: 'low',
    detail: 'Log.d output is readable via logcat by any app with READ_LOGS (pre-4.1) or via ADB. Tokens, URLs, and internal state logged in debug builds often ship to production. Strip or gate them.',
  },
  'Hardcoded crypto key possible (check SecretKeySpec)': {
    fix: 'Do not hardcode keys in SecretKeySpec. Use Android Keystore.',
    priority: 'medium',
    detail: 'A key embedded in the APK is extractable by anyone who downloads the app (apktool/jadx in minutes). Encryption with a known key provides zero confidentiality. Store keys in Android Keystore, ideally with hardware backing and user authentication binding.',
  },
  'Dynamic code loading (DexClassLoader)': {
    fix: 'Audit DexClassLoader sources. Only load from trusted, verified locations.',
    priority: 'medium',
    detail: 'Loading DEX/JAR at runtime from writable locations (sdcard, downloads, app cache) lets an attacker replace the payload and achieve code execution in your process. If used for plugins, verify signatures before loading and prefer Play Asset Delivery.',
  },
  'Shell command execution': {
    fix: 'Avoid Runtime.exec(). Validate and sanitize all command inputs to prevent injection.',
    priority: 'medium',
    detail: 'Runtime.exec with unsanitized input is shell injection. Even without a shell, argument injection can alter behavior. Prefer Android APIs over shelling out; if unavoidable, use a fixed command array and never interpolate untrusted strings.',
  },
};
function suggestForFinding(finding) {
  // Direct match
  if (SUGGESTIONS[finding.msg]) return { ...SUGGESTIONS[finding.msg], finding: finding.msg };
  // Pattern matches
  if (finding.msg.startsWith('Critical permission:')) {
    const perm = finding.msg.split(': ')[1];
    return {
      finding: finding.msg,
      fix: `Verify ${perm} is essential. If used only in one feature, request it at runtime with justification (Android 6+). Remove if unused (over-declaration).`,
      priority: 'medium',
    };
  }
  if (finding.msg.includes('exported components')) {
    return {
      finding: finding.msg,
      fix: 'Set android:exported="false" on components that do not need external access. Add permission guards on the ones that do.',
      priority: 'medium',
    };
  }
  if (finding.msg.includes('declared but never used')) {
    return {
      finding: finding.msg,
      fix: 'Remove the permission from AndroidManifest.xml if truly unused. Over-declared permissions erode user trust.',
      priority: 'low',
    };
  }
  if (finding.msg.includes('in code') || finding.msg.includes('secrets')) {
    return {
      finding: finding.msg,
      fix: 'Move secrets to server-side or use Android Keystore. Never hardcode API keys in the APK.',
      priority: 'high',
    };
  }
  if (finding.msg.includes('cleartext URLs')) {
    return {
      finding: finding.msg,
      fix: 'Replace http:// with https:// endpoints.',
      priority: 'medium',
    };
  }
  return null;
}

function generateSuggestions(findings) {
  return findings.map(suggestForFinding).filter(Boolean);
}

module.exports = { generateSuggestions };
