// Config: ~/.config/apkator/config.json
// {
//   "ai": {
//     "provider": "nim" | "openai" | "custom" | "none",
//     "baseUrl": "https://...",
///     "model": "z-ai/glm-5.3-flash",
//     "apiKey": "env:VAR_NAME" | "literal:key"
//   }
// }
const fs = require('fs');
const path = require('path');
const os = require('os');

const CONFIG_PATH = path.join(os.homedir(), '.config', 'apkator', 'config.json');

function load() {
  const defaults = { ai: { provider: 'none' } };
  try {
    if (fs.existsSync(CONFIG_PATH)) {
      return { ...defaults, ...JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8')) };
    }
  } catch (e) {}
  return defaults;
}

function resolveKey(keySpec) {
  if (!keySpec) return null;
  if (keySpec.startsWith('env:')) return process.env[keySpec.slice(4)] || null;
  return keySpec;
}

function getAIConfig() {
  const cfg = load();
  const ai = cfg.ai || { provider: 'none' };
  if (ai.provider === 'none') return null;
  return {
    provider: ai.provider,
    baseUrl: ai.baseUrl,
    model: ai.model || 'z-ai/glm-5.3-flash',
    apiKey: resolveKey(ai.apiKey),
  };
}

function initConfig() {
  const dir = path.dirname(CONFIG_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(CONFIG_PATH)) {
    fs.writeFileSync(CONFIG_PATH, JSON.stringify({
      ai: {
        provider: 'none',
        _comment: 'Set to "nim", "openai" or "custom". Configure baseUrl, model and apiKey (use "env:VAR" for env vars).',
      }
    }, null, 2));
  }
  return CONFIG_PATH;
}

module.exports = { load, getAIConfig, initConfig, CONFIG_PATH };
