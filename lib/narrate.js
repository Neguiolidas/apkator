// AI narrative layer: digest -> 3-5 sentence explanation
// Works with any OpenAI-compatible API. Falls back to deterministic template.
const https = require('https');
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const os = require('os');
const { getAIConfig } = require('./config');

const CACHE_DIR = path.join(os.homedir(), '.cache', 'apkator', 'narrative');

function buildDigest(R) {
  const high = R.findings.filter(f => f.sev === 'high').map(f => f.msg);
  const med = R.findings.filter(f => f.sev === 'medium').map(f => f.msg);
  const critPerms = R.permissions.filter(p => p.level === 'critical').map(p => p.name);
  return JSON.stringify({
    pkg: R.package, ver: R.version, cat: R.category || 'unknown',
    score: R.score, high, med: med.slice(0, 5),
    critPerms, trackers: R.trackers,
    domains: R.domains.slice(0, 10),
    flows: (R.flows || []).slice(0, 5).map(f => `${f.perm} -> ${f.domain} [${f.conf}]`),
  });
}

function deterministicNarrative(R) {
  const cat = R.category || 'app';
  const high = R.findings.filter(f => f.sev === 'high');
  const crit = R.permissions.filter(p => p.level === 'critical');
  const parts = [];
  parts.push(`This is a ${cat} (${R.package} v${R.version}) with privacy score ${R.score}/100.`);
  if (crit.length) parts.push(`It requests sensitive access: ${crit.map(p => p.desc.toLowerCase()).join(', ')}.`);
  if (R.flows && R.flows.length) {
    const f = R.flows[0];
    parts.push(`Data flow detected: ${f.perm} connects to ${f.domain}.`);
  }
  if (high.length) parts.push(`Main concern: ${high[0].msg.toLowerCase()}.`);
  else if (R.score >= 70) parts.push('No critical issues found.');
  return parts.join(' ');
}

function callAI(digest, aiCfg) {
  return new Promise((resolve) => {
    const url = new URL(aiCfg.baseUrl + '/chat/completions');
    const body = JSON.stringify({
      model: aiCfg.model,
      max_tokens: 400,
      messages: [
        { role: 'system', content: 'You are a mobile security analyst. Explain in 3-5 direct sentences what this Android app does and what is suspicious. No jargon, no emoji, no bullet points. Plain paragraphs.' },
        { role: 'user', content: `Analyze this APK scan result:\n${digest}` },
      ],
    });
    const lib = url.protocol === 'https:' ? https : http;
    const req = lib.request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...(aiCfg.apiKey ? { 'Authorization': `Bearer ${aiCfg.apiKey}` } : {}) },
      timeout: 30000,
    }, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const j = JSON.parse(data);
          const content = j.choices?.[0]?.message?.content;
          resolve(content || null);
        } catch (e) { resolve(null); }
      });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.write(body);
    req.end();
  });
}

async function narrate(R) {
  const digest = buildDigest(R);
  const hash = crypto.createHash('sha256').update(digest).digest('hex').slice(0, 16);
  const cacheFile = path.join(CACHE_DIR, `${hash}.txt`);

  // Cache hit
  try {
    if (fs.existsSync(cacheFile)) return { text: fs.readFileSync(cacheFile, 'utf8'), source: 'cache' };
  } catch (e) {}

  // Try AI
  const aiCfg = getAIConfig();
  if (aiCfg && aiCfg.baseUrl) {
    const text = await callAI(digest, aiCfg);
    if (text) {
      try {
        fs.mkdirSync(CACHE_DIR, { recursive: true });
        fs.writeFileSync(cacheFile, text);
      } catch (e) {}
      return { text, source: 'ai' };
    }
  }

  // Deterministic fallback
  return { text: deterministicNarrative(R), source: 'deterministic' };
}

module.exports = { narrate };
