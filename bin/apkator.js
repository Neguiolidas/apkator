#!/usr/bin/env node
// apkator v0.6
const { execSync, spawnSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const LIB = path.join(__dirname, '..', 'lib');
const { getAIConfig, initConfig, CONFIG_PATH } = require(path.join(LIB, 'config.js'));
const { generateSuggestions } = require(path.join(LIB, 'suggest.js'));
const { narrate } = require(path.join(LIB, 'narrate.js'));
const FLOWS = require(path.join(LIB, 'flows.json'));
const BASELINES = require(path.join(LIB, 'baselines.json'));

const APKTOOL = process.env.APKTOOL_DIR || path.join(os.homedir(), 'workspace', 'tools', 'apk');
const WORKDIR = path.join(__dirname, '..');
const DECODE_CACHE = path.join(os.homedir(), '.cache', 'apkator', 'decode');

const PERMS = {
  'android.permission.RECORD_AUDIO': ['critical', 'Microphone'],
  'android.permission.CAMERA': ['critical', 'Camera'],
  'android.permission.READ_CONTACTS': ['critical', 'Contacts'],
  'android.permission.READ_SMS': ['critical', 'SMS'],
  'android.permission.READ_CALL_LOG': ['critical', 'Call history'],
  'android.permission.ACCESS_FINE_LOCATION': ['critical', 'Precise GPS'],
  'android.permission.ACCESS_BACKGROUND_LOCATION': ['critical', 'Background location'],
  'android.permission.READ_PHONE_STATE': ['warning', 'Phone identifiers'],
  'android.permission.READ_EXTERNAL_STORAGE': ['warning', 'Storage read'],
  'android.permission.CALL_PHONE': ['warning', 'Direct calls'],
  'android.permission.SYSTEM_ALERT_WINDOW': ['warning', 'Overlay'],
  'android.permission.QUERY_ALL_PACKAGES': ['warning', 'List installed apps'],
  'android.permission.REQUEST_INSTALL_PACKAGES': ['warning', 'Install apps'],
  'android.permission.SEND_SMS': ['warning', 'Send SMS'],
  'android.permission.INTERNET': ['info', 'Internet'],
  'android.permission.ACCESS_NETWORK_STATE': ['info', 'Network state'],
  'android.permission.VIBRATE': ['info', 'Vibrate'],
  'android.permission.WAKE_LOCK': ['info', 'Wake lock'],
  'android.permission.RECEIVE_BOOT_COMPLETED': ['info', 'Boot start'],
  'android.permission.POST_NOTIFICATIONS': ['info', 'Notifications'],
  'android.permission.FOREGROUND_SERVICE': ['info', 'Foreground service'],
  'android.permission.BLUETOOTH': ['info', 'Bluetooth'],
  'android.permission.NFC': ['info', 'NFC'],
};
const NOISE = ['schemas.android.com', 'www.w3.org', 'developer.android.com'];
function sh(c, t = 30000) { try { return execSync(c, { encoding: 'utf8', stdio: 'pipe', timeout: t }); } catch (e) { return ''; } }
function sha256(f) { return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex'); }

function decode(apk, deep) {
  const hash = sha256(apk).slice(0, 16) + (deep ? '-deep' : '-fast');
  const cached = path.join(DECODE_CACHE, hash);
  if (fs.existsSync(path.join(cached, 'AndroidManifest.xml'))) {
    process.stderr.write('Using cached decode... ok\n');
    return { tmp: null, D: cached, cached: true };
  }
  const tmp = fs.mkdtempSync(path.join(WORKDIR, 'tmp-'));
  const D = `${tmp}/d`;
  process.stderr.write(deep ? 'Decoding (deep)... ' : 'Decoding (fast)... ');
  const args = ['-jar', `${APKTOOL}/apktool.jar`, 'd', apk, '-o', D, '-f'];
  if (!deep) args.push('-s');
  spawnSync('java', args, { stdio: 'pipe', timeout: 280000 });
  if (!fs.existsSync(`${D}/AndroidManifest.xml`)) { console.error('decode failed'); process.exit(1); }
  // Cache it
  try {
    fs.mkdirSync(DECODE_CACHE, { recursive: true });
    sh(`cp -r "${D}" "${cached}"`, 60000);
  } catch (e) {}
  process.stderr.write('ok\n');
  return { tmp, D, cached: false };
}

function detectCategory(pkg, perms) {
  let best = null, bestScore = 0;
  const permNames = perms.map(p => p.name);
  for (const [cat, base] of Object.entries(BASELINES)) {
    let score = 0;
    const kwHit = base.keywords.some(k => pkg.toLowerCase().includes(k)) ? 1 : 0;
    const exp = base.expected.filter(p => permNames.includes(p)).length / Math.max(1, base.expected.length);
    score = 0.5 * kwHit + 0.5 * exp;
    if (score > bestScore) { bestScore = score; best = cat; }
  }
  return bestScore >= 0.35 ? { name: best, score: +bestScore.toFixed(2) } : { name: 'unknown', score: 0 };
}

function analyze(D, apkPath, deep) {
  const R = { findings: [], flows: [] };
  const manifest = fs.readFileSync(`${D}/AndroidManifest.xml`, 'utf8');
  R.package = (manifest.match(/package="([^"]+)"/) || [])[1] || '?';
  R.version = (manifest.match(/versionName="([^"]+)"/) || [])[1];
  if (!R.version) {
    try {
      const yml = fs.readFileSync(`${D}/apktool.yml`, 'utf8');
      const ym = yml.match(/versionName:\s*['"]?([^'"\n]+)/);
      if (ym) R.version = ym[1].trim();
    } catch (e) {}
  }
  R.version = R.version || 'unknown';

  R.manifest = {
    debuggable: manifest.includes('android:debuggable="true"'),
    allowBackup: !manifest.includes('android:allowBackup="false"'),
    cleartext: manifest.includes('android:usesCleartextTraffic="true"'),
  };
  if (R.manifest.debuggable) R.findings.push({ sev: 'high', cat: 'manifest', msg: 'Debuggable enabled' });
  if (R.manifest.allowBackup) R.findings.push({ sev: 'medium', cat: 'manifest', msg: 'Backup allowed' });
  if (R.manifest.cleartext) R.findings.push({ sev: 'high', cat: 'manifest', msg: 'Cleartext traffic allowed' });

  const rawP = [...manifest.matchAll(/uses-permission[^>]*android:name="([^"]+)"/g)].map(m => m[1]);
  R.permissions = [...new Set(rawP)].map(p => {
    const i = PERMS[p];
    return { name: p.replace('android.permission.', ''), level: i ? i[0] : 'other', desc: i ? i[1] : p };
  });

  const expCount = (manifest.match(/android:exported="true"/g) || []).length;
  R.exportedCount = expCount;
  if (expCount > 5) R.findings.push({ sev: 'medium', cat: 'manifest', msg: `${expCount} exported components` });

  // Manifest hardening checks
  if (/android:taskAffinity="[^"]+"/.test(manifest) && !/android:taskAffinity=""/.test(manifest))
    R.findings.push({ sev: 'low', cat: 'manifest', msg: 'Custom taskAffinity (task hijacking risk)' });
  const deepLinks = (manifest.match(/<data[^>]*android:scheme="[^"]+"/g) || []).length;
  const autoVerify = (manifest.match(/android:autoVerify="true"/g) || []).length;
  if (deepLinks > autoVerify)
    R.findings.push({ sev: 'low', cat: 'manifest', msg: `${deepLinks - autoVerify} deep links without autoVerify` });
  if (!manifest.includes('networkSecurityConfig'))
    R.findings.push({ sev: 'low', cat: 'manifest', msg: 'No networkSecurityConfig (no cert pinning)' });
  const providers = [...manifest.matchAll(/<provider[^>]*>/g)];
  const unprotectedProviders = providers.filter(p => !/android:(permission|readPermission|writePermission)=/.test(p[0]) && /android:exported="true"/.test(p[0]));
  if (unprotectedProviders.length)
    R.findings.push({ sev: 'high', cat: 'manifest', msg: `${unprotectedProviders.length} exported providers without permission` });

  // Category + anomalies
  R.category = detectCategory(R.package, R.permissions).name;
  if (R.category !== 'unknown') {
    const base = BASELINES[R.category];
    R.permissions.filter(p => ['critical', 'warning'].includes(p.level) && base.rare.includes(p.name))
      .forEach(p => R.findings.push({ sev: 'medium', cat: 'anomaly', msg: `Anomaly: ${p.name} unusual for ${R.category}` }));
  }

  // Deep-only: flows, secrets, trackers
  if (deep && fs.existsSync(`${D}/smali`)) {
    // Data flows: single combined grep for all API signatures
    const allSigs = Object.values(FLOWS).flat();
    const grepPat = allSigs.map(s => `-e "${s.replace(/\(/g, '\\(')}"`).join(' ');
    const candidates = sh(`grep -rl ${grepPat} "${D}/smali" 2>/dev/null | head -50`, 90000).trim().split('\n').filter(Boolean);

    for (const file of candidates.slice(0, 30)) {
      try {
        const content = fs.readFileSync(file, 'utf8');
        const methods = content.split(/^\.method /m);
        for (const m of methods) {
          for (const [perm, sigs] of Object.entries(FLOWS)) {
            const hit = sigs.find(s => m.includes(s.replace(/\\\(/g, '(')));
            if (hit) {
              const urls = [...m.matchAll(/const-string[^"]*"((https?:\/\/[^"]+))"/g)].map(x => x[1]);
              const domains = [...new Set(urls.map(u => u.replace(/^https?:\/\//, '').split('/')[0]).filter(d => d && !NOISE.includes(d)))];
              const hasNet = /OkHttp|Retrofit|HttpURLConnection|DefaultHttpClient/.test(m) || domains.length > 0;
              if (hasNet && domains.length) {
                domains.slice(0, 3).forEach(d => R.flows.push({ perm, api: hit.split(';->')[1] || hit, domain: d, conf: 'method', via: path.basename(file) }));
              } else if (hasNet) {
                R.flows.push({ perm, api: hit.split(';->')[1] || hit, domain: '(network call)', conf: 'method', via: path.basename(file) });
              }
            }
          }
        }
      } catch (e) {}
    }
    // Dedupe flows
    const seen = new Set();
    R.flows = R.flows.filter(f => { const k = `${f.perm}|${f.domain}`; if (seen.has(k)) return false; seen.add(k); return true; }).slice(0, 10);

    // Over-declaration: permission in manifest but no smali hits
    for (const [perm, sigs] of Object.entries(FLOWS)) {
      const short = perm.replace('android.permission.', '');
      if (R.permissions.some(p => p.name === short)) {
        const used = sh(`grep -rl -e "${sigs[0].replace(/\(/g, '\\(')}" "${D}/smali" 2>/dev/null | head -1`, 30000).trim();
        if (!used) R.findings.push({ sev: 'low', cat: 'privacy', msg: `${short} declared but never used in code` });
      }
    }

    // Secrets (combined grep)
    const secretHit = sh(`grep -rl -e "sk-[a-zA-Z0-9]\\{20,\\}" -e "AIza[a-zA-Z0-9_-]\\{35\\}" -e "BEGIN.*PRIVATE KEY" "${D}/smali" 2>/dev/null | head -3`, 60000).trim();
    if (secretHit) R.findings.push({ sev: 'high', cat: 'code', msg: 'Hardcoded secrets in code' });

    // Vulnerability checks (batched grep for efficiency)
    const vulnChecks = [
      { pat: 'MessageDigest.getInstance("MD5")', msg: 'MD5 hash usage (broken)', sev: 'medium' },
      { pat: 'MessageDigest.getInstance("SHA-1")', msg: 'SHA-1 hash usage (weak)', sev: 'low' },
      { pat: 'Cipher.getInstance("DES', msg: 'DES encryption (broken)', sev: 'high' },
      { pat: '/ECB/', msg: 'ECB cipher mode (leaks patterns)', sev: 'medium' },
      { pat: 'addJavascriptInterface', msg: 'WebView JS bridge (XSS risk)', sev: 'medium' },
      { pat: 'setAllowFileAccess(1)', msg: 'WebView file access enabled', sev: 'medium' },
      { pat: 'ALLOW_ALL_HOSTNAME_VERIFIER', msg: 'SSL hostname verification disabled', sev: 'high' },
      { pat: 'checkServerTrusted', msg: 'Custom TrustManager (MITM risk)', sev: 'medium' },
      { pat: 'rawQuery(', msg: 'Raw SQL query (injection risk)', sev: 'low' },
      { pat: 'java/util/Random', msg: 'Insecure Random (not SecureRandom)', sev: 'low' },
      { pat: 'MODE_WORLD_READABLE', msg: 'World-readable file mode', sev: 'medium' },
      { pat: 'MODE_WORLD_WRITEABLE', msg: 'World-writable file mode', sev: 'high' },
      { pat: 'getDeviceId()', msg: 'IMEI access (persistent identifier)', sev: 'medium' },
      { pat: 'getSubscriberId()', msg: 'IMSI access (persistent identifier)', sev: 'medium' },
      { pat: 'IvParameterSpec', msg: 'Hardcoded IV possible (check IvParameterSpec usage)', sev: 'low' },
      { pat: 'SecretKeySpec', msg: 'Hardcoded crypto key possible (check SecretKeySpec)', sev: 'medium' },
      { pat: 'DexClassLoader', msg: 'Dynamic code loading (DexClassLoader)', sev: 'medium' },
      { pat: 'Runtime.getRuntime().exec(', msg: 'Shell command execution', sev: 'medium' },
      { pat: 'Log.d(', msg: 'Debug logging in release (info leak)', sev: 'low' },
      { pat: 'sendBroadcast(', msg: 'Implicit broadcast (use explicit)', sev: 'low' },
    ];
    // Single grep with all patterns, then map hits back
    const allPats = vulnChecks.map(v => `-F -e '${v.pat}'`).join(' ');
    const vulnOut = sh(`grep -rl ${allPats} "${D}/smali" 2>/dev/null | head -30`, 90000).trim().split('\n').filter(Boolean);
    if (vulnOut.length) {
      // For each file, check which patterns hit
      const hitPats = new Set();
      for (const f of vulnOut.slice(0, 20)) {
        try {
          const c = fs.readFileSync(f, 'utf8');
          vulnChecks.forEach(v => { if (c.includes(v.pat)) hitPats.add(v.msg); });
        } catch (e) {}
      }
      vulnChecks.forEach(v => { if (hitPats.has(v.msg)) R.findings.push({ sev: v.sev, cat: 'vuln', msg: v.msg }); });
    }

    // Trackers
    R.trackers = [];
    for (const sig of ['com/google/android/gms/analytics', 'com/facebook/appevents', 'com/amplitude']) {
      if (sh(`find "${D}/smali" -type d -path "*${sig}*" 2>/dev/null | head -1`, 20000).trim()) R.trackers.push(sig.split('/').pop());
    }
  } else {
    R.trackers = [];
  }

  // Domains (fast: from res + manifest)
  const urlSrc = deep ? `"${D}/smali" "${D}/res"` : `"${D}/res" "${D}/AndroidManifest.xml"`;
  const urlOut = sh(`grep -rhoE "https?://[a-zA-Z0-9.-]+\\.[a-z]{2,}" ${urlSrc} 2>/dev/null | sort -u`, 60000);
  R.domains = urlOut.trim() ? [...new Set(urlOut.trim().split('\n').map(u => u.replace(/^https?:\/\//, '').split('/')[0]).filter(d => d && !NOISE.includes(d) && d.includes('.')))].slice(0, 15) : [];

  // Score
  let score = 100;
  R.findings.forEach(f => { score -= f.sev === 'high' ? 15 : f.sev === 'medium' ? 7 : 3; });
  R.score = Math.max(0, Math.min(100, score));
  R.file = path.basename(apkPath);
  R.deep = deep;
  return R;
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--help') || args.includes('-h')) {
    console.log(`apkator — Android APK security analysis
Usage: apkator <file.apk> [options]
  --deep       full smali analysis (flows, vulns, secrets)
  --explain    AI-powered narrative (requires --init config)
  --show=x     detail view: permissions|manifest|code|network|all
  --json       machine-readable output
  --init       create AI provider config
  --help       this help`);
    return;
  }
  if (args.includes('--init')) { console.log('Config created at: ' + initConfig()); return; }
  const apk = args.find(a => !a.startsWith('-'));
  const deep = args.includes('--deep');
  const explain = args.includes('--explain');
  const jsonOut = args.includes('--json');
  const section = (args.find(a => a.startsWith('--show=')) || '').split('=')[1];
  if (!apk || !fs.existsSync(apk)) {
    console.error('Usage: apkator <file.apk> [--deep] [--explain] [--show=x] [--json] [--init]');
    console.error('  --init     create config file for AI provider');
    process.exit(1);
  }

  const t0 = Date.now();
  const { tmp, D } = decode(apk, deep);
  const R = analyze(D, apk, deep);
  R.elapsed = +((Date.now() - t0) / 1000).toFixed(0);
  if (tmp) sh(`rm -rf "${tmp}"`);

  // Suggestions (deterministic, always)
  R.suggestions = generateSuggestions(R.findings);

  // Narrative (AI or deterministic)
  const n = await narrate(R);
  R.narrative = n.text;
  R.narrativeSource = n.source;

  if (jsonOut) { console.log(JSON.stringify(R, null, 2)); return; }

  // Detail view for --show=
  if (section) {
    const L = [`\n  ${R.package} v${R.version} — ${section}`];
    if (section === 'permissions' || section === 'all') {
      L.push('\n  PERMISSIONS');
      R.permissions.forEach(p => L.push(`    [${p.level}] ${p.name} — ${p.desc}`));
    }
    if (section === 'manifest' || section === 'all') {
      L.push('\n  MANIFEST');
      L.push(`    debuggable: ${R.manifest.debuggable}`);
      L.push(`    allowBackup: ${R.manifest.allowBackup}`);
      L.push(`    cleartext: ${R.manifest.cleartext}`);
      L.push(`    exported components: ${R.exportedCount}`);
    }
    if (section === 'code' || section === 'all') {
      L.push('\n  CODE FINDINGS');
      R.findings.filter(f => ['vuln', 'code'].includes(f.cat)).forEach(f => L.push(`    [${f.sev.toUpperCase()}] ${f.msg}`));
    }
    if (section === 'network' || section === 'all') {
      L.push('\n  NETWORK');
      R.domains.forEach(d => L.push(`    ${d}`));
      if (R.flows.length) {
        L.push('\n  DATA FLOWS');
        R.flows.forEach(f => L.push(`    ${f.perm} --[${f.api}]--> ${f.domain} [${f.conf}]`));
      }
      if (R.trackers.length) L.push(`\n  Trackers: ${R.trackers.join(', ')}`);
    }
    if (section === 'all') {
      L.push('\n  ALL FINDINGS');
      R.findings.forEach(f => L.push(`    [${f.sev.toUpperCase()}] [${f.cat}] ${f.msg}`));
    }
    L.push('');
    console.log(L.join('\n'));
    return;
  }

  const L = [];
  L.push(`\n  ${R.package} v${R.version} — score ${R.score}/100 (${R.elapsed}s)${deep ? ' [deep]' : ''}`);
  if (R.category !== 'unknown') L.push(`  Category: ${R.category}`);

  // Narrative
  if (R.narrative) { L.push(''); L.push(`  ${R.narrative}`); }

  // Flows
  if (R.flows.length) {
    L.push('\n  DATA FLOWS');
    R.flows.forEach(f => L.push(`    ${f.perm} --[${f.api}]--> ${f.domain} [${f.conf}]`));
  }

  // Findings
  const high = R.findings.filter(f => f.sev === 'high');
  const med = R.findings.filter(f => f.sev === 'medium');
  if (high.length || med.length) {
    L.push(`\n  Findings: ${high.length} high, ${med.length} medium`);
    high.forEach(f => L.push(`    [HIGH] ${f.msg}`));
    med.forEach(f => L.push(`    [MED]  ${f.msg}`));
  }

  // Suggestions
  if (R.suggestions.length && !section) {
    L.push('\n  SUGGESTIONS');
    R.suggestions.slice(0, 5).forEach(s => L.push(`    [${s.priority.toUpperCase()}] ${s.finding}\n      Fix: ${s.fix}`));
  }

  const crit = R.permissions.filter(p => p.level === 'critical').length;
  L.push(`\n  ${R.permissions.length} permissions (${crit} critical), ${R.domains.length} domains`);
  L.push('\n  Detail: --show=permissions|manifest|code|network|all  Deep: --deep  AI: --explain  Config: --init');
  L.push('');
  console.log(L.join('\n'));
}
main().catch(e => { console.error('Error:', e.message); process.exit(1); });
