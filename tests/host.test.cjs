'use strict';
// Both bundles inside Vetro's real plugin host (from a Vetro checkout), behind a real HTTP server:
// install with Developer mode, switch on, call the pages and routes as the dashboard would, switch off.
const assert = require('assert').strict, fs = require('fs'), os = require('os'), path = require('path'), http = require('http'), cp = require('child_process');
const vetro = [process.env.VETRO_DIR, path.join(__dirname, '../../vetro'), path.join(__dirname, '../../vetro-0.5.0')]
  .filter(Boolean).map(d => path.resolve(d)).find(d => fs.existsSync(path.join(d, 'app/service/plugin-host.js')));
if (!vetro) { console.log('SKIP host test: set VETRO_DIR to a Vetro 0.5+ checkout'); process.exit(0); }
const { PluginHost } = require(path.join(vetro, 'app/service/plugin-host.js'));
const tool = path.join(vetro, 'app/scripts/vetro-plugin.cjs');

(async () => {
  const out = fs.mkdtempSync(path.join(os.tmpdir(), 'shard-pack-')), dir = fs.mkdtempSync(path.join(os.tmpdir(), 'shard-host-'));
  const bundles = {};
  for (const id of ['shell', 'nordvpn']) {
    const r = cp.spawnSync(process.execPath, [tool, 'pack', path.join(__dirname, '..', id)], { cwd: out, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr); const file = fs.readdirSync(out).find(f => f.startsWith(id + '-'));
    bundles[id] = fs.readFileSync(path.join(out, file), 'utf8');
  }
  const commands = [];
  const execute = (cmd) => { commands.push(cmd); const s = /^echo (\S+) \| base64 -d \| sh$/.exec(cmd);
    const text = s ? Buffer.from(s[1], 'base64').toString() : cmd;
    if (/nordtv (state|status -json)/.test(text)) return Promise.resolve({ exit_code: 0, stdout: '{"running":false,"country":"IT","killswitch":true,"enabled":false,"autostart":true,"hasToken":true}\n' });
    return new Promise(res => { const p = cp.spawnSync('/bin/sh', ['-c', cmd], { encoding: 'utf8' }); res({ exit_code: p.status, stdout: p.stdout, stderr: p.stderr }); }); };
  const host = new PluginHost({ dir, execute, stableMs: 10 });
  host._writeState({ enabled: {}, developer: true });
  for (const id of ['shell', 'nordvpn']) { host.install(bundles[id]); assert.equal(host.setEnabled(id, true).state, 'running', id + ' starts in the host'); }

  const json = (res, body, code) => { res.writeHead(code || 200, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  const server = http.createServer((req, res) => { if (!host.handle(req, res, req.url.split('?')[0], json)) json(res, { error: 'not found' }, 404); });
  await new Promise(r => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const get = u => fetch(base + u), post = (u, b) => fetch(base + u, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(b) });

  let r = await get('/plugins/shell/api/ui'); assert.equal(r.status, 200); assert.ok((await r.text()).includes('<title>Shell</title>'));
  assert.equal(r.headers.get('content-security-policy'), 'sandbox allow-scripts', 'served sandboxed by the host');
  r = await post('/plugins/shell/api/run', { cmd: 'echo from-host; cd /tmp' }); let j = await r.json();
  assert.equal(j.stdout, 'from-host\n'); assert.equal(fs.realpathSync(j.cwd), fs.realpathSync('/tmp'));
  r = await get('/plugins/nordvpn/api/ui'); assert.ok((await r.text()).includes('<title>NordVPN</title>'));
  r = await get('/plugins/nordvpn/api/state'); j = await r.json(); assert.equal(j.installed, true); assert.equal(j.country, 'IT');
  r = await get('/plugins/nordvpn'); j = await r.json(); assert.equal(j.state, 'running');
  for (const id of ['shell', 'nordvpn']) assert.notEqual(host.setEnabled(id, false).state, 'running', id + ' stops cleanly');
  r = await get('/plugins/shell/api/ui'); assert.equal(r.status, 503, 'routes close when switched off');
  server.close(); fs.rmSync(out, { recursive: true, force: true }); fs.rmSync(dir, { recursive: true, force: true });
  console.log('PASS host: both bundles install, start, serve their pages and routes inside Vetro ' + require(path.join(vetro, 'app/package.json')).version + "'s plugin host, and stop");
})().catch(e => { console.error(e); process.exitCode = 1; });
