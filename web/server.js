const http = require('http');
const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');

const PORT = 8735;
const PUB = path.join(__dirname, 'public');
const BIN = path.join(__dirname, '..', 'bin', 'apkator.js');
const UPLOAD = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD)) fs.mkdirSync(UPLOAD, { recursive: true });

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'application/javascript', '.json': 'application/json' };

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://localhost:${PORT}`);

  // API: get AI config
  if (url.pathname === '/api/config' && req.method === 'GET') {
    const { load, CONFIG_PATH } = require(path.join(__dirname, '..', 'lib', 'config.js'));
    const cfg = load();
    // Never expose raw API key
    if (cfg.ai && cfg.ai.apiKey && !cfg.ai.apiKey.startsWith('env:')) {
      cfg.ai.apiKey = '***configured***';
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(cfg));
    return;
  }

  // API: save AI config
  if (url.pathname === '/api/config' && req.method === 'POST') {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => {
      try {
        const { load, CONFIG_PATH } = require(path.join(__dirname, '..', 'lib', 'config.js'));
        const incoming = JSON.parse(body);
        const cfg = load();
        cfg.ai = {
          provider: incoming.provider || 'none',
          baseUrl: incoming.baseUrl || '',
          model: incoming.model || '',
          apiKey: incoming.apiKey || '',
        };
        fs.mkdirSync(path.dirname(CONFIG_PATH), { recursive: true });
        fs.writeFileSync(CONFIG_PATH, JSON.stringify(cfg, null, 2));
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true }));
      } catch (e) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: e.message }));
      }
    });
    return;
  }

  // API: analyze
  if (url.pathname === '/api/analyze' && req.method === 'POST') {
    let body = Buffer.alloc(0);
    req.on('data', c => { body = Buffer.concat([body, c]); });
    req.on('end', () => {
      const boundary = req.headers['content-type'].split('boundary=')[1];
      const parts = body.toString('binary').split(boundary);
      let apkBuf = null, apkName = 'upload.apk';
      for (const p of parts) {
        if (p.includes('filename="')) {
          apkName = (p.match(/filename="([^"]+)"/) || [])[1] || 'upload.apk';
          const start = p.indexOf('\r\n\r\n') + 4;
          const end = p.lastIndexOf('\r\n');
          apkBuf = Buffer.from(p.slice(start, end), 'binary');
        }
      }
      if (!apkBuf) { res.writeHead(400); res.end('no file'); return; }
      const deep = url.searchParams.get('deep') === '1';
      const explain = url.searchParams.get('explain') === '1';
      const fpath = path.join(UPLOAD, `${Date.now()}-${apkName.replace(/[^a-zA-Z0-9.-]/g, '_')}`);
      fs.writeFileSync(fpath, apkBuf);

      const args = [BIN, fpath, '--json'];
      if (deep) args.push('--deep');
      if (explain) args.push('--explain');
      execFile('node', args, { timeout: 280000, maxBuffer: 50 * 1024 * 1024 }, (err, stdout) => {
        fs.unlink(fpath, () => {});
        if (err) { res.writeHead(500, { 'Content-Type': 'application/json' }); res.end(JSON.stringify({ error: 'analysis failed' })); return; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(stdout);
      });
    });
    return;
  }

  // Static
  let fpath = path.join(PUB, url.pathname === '/' ? 'index.html' : url.pathname.slice(1));
  if (!fpath.startsWith(PUB)) { res.writeHead(403); res.end(); return; }
  fs.readFile(fpath, (err, data) => {
    if (err) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(fpath)] || 'text/plain' });
    res.end(data);
  });
});

server.listen(PORT, () => console.log(`Apkator web on http://localhost:${PORT}`));
