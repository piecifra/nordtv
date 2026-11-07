'use strict';
const assert = require('assert').strict, fs = require('fs'), os = require('os'), path = require('path'), zlib = require('zlib'), crypto = require('crypto'), cp = require('child_process');
const plugin = require('../nordvpn/index.js'), { Vpn, validate, installScript } = plugin;

// A fake TV: decodes each wrapped script and answers like the nordtv binary would.
function fakeTv(initial) {
  const tv = Object.assign({ installed: true, running: false, country: 'IT', killswitch: true, autostart: true, enabled: false, hasToken: true, token: null, startFails: false, scripts: [] }, initial || {});
  tv.execute = async cmd => {
    const m = /^echo (\S+) \| base64 -d \| sh$/.exec(cmd); assert.ok(m, 'commands are wrapped');
    const s = Buffer.from(m[1], 'base64').toString(); tv.scripts.push(s);
    if (/curl /.test(s)) return { exit_code: 0, stdout: tv.download || '__DOWNLOAD_FAILED__\n' };
    assert.ok(s.includes('mv -f /dev/shm/nordtv.new /dev/shm/nordtv'), 'binary is staged in /dev/shm first');
    if (!tv.installed) return { exit_code: 0, stdout: '__NOBIN__\n' };
    let out = '';
    const cc = /set country "([A-Z]*)"/.exec(s); if (cc) tv.country = cc[1];
    const ks = /set killswitch (on|off)/.exec(s); if (ks) tv.killswitch = ks[1] === 'on';
    const au = /set autostart (on|off)/.exec(s); if (au) tv.autostart = au[1] === 'on';
    const tok = /echo (\S+) \| base64 -d > \/opt\/nordtv\/token\.new/.exec(s); if (tok) { tv.token = Buffer.from(tok[1], 'base64').toString().trim(); tv.hasToken = true; }
    if (/nordtv start/.test(s)) { if (tv.startFails) return { exit_code: 1, stdout: 'fetching NordLynx key (check token): HTTP 401\n' }; tv.running = true; tv.enabled = true; }
    if (/nordtv stop/.test(s)) { tv.running = false; tv.enabled = false; }
    if (/nordtv verify/.test(s)) out += JSON.stringify(tv.token === 'goodtoken0123456789' ? { ok: true } : { ok: false, error: 'token rejected by NordVPN' }) + '\n';
    if (/nordtv countries/.test(s)) out += 'IT\tItaly\nCH\tSwitzerland\nbogus\n';
    if (/nordtv (state|status -json)/.test(s)) {
      const st = { running: tv.running, country: tv.country, killswitch: tv.killswitch, enabled: tv.enabled, autostart: tv.autostart, hasToken: tv.hasToken };
      if (tv.running && /status -json/.test(s)) Object.assign(st, { server: 'it455.nordvpn.com', publicIp: '198.51.100.7', protected: true });
      out += JSON.stringify(st) + '\n';
    }
    return { exit_code: 0, stdout: out };
  };
  return tv;
}
const starts = tv => tv.scripts.filter(x => /nordtv start/.test(x)).length;

(async () => {
  assert.deepEqual(validate({ country: 'CH', killswitch: false }), { country: 'CH', killswitch: false });
  for (const bad of [{ country: 'it' }, { country: 'I"; reboot; "' }, { killswitch: 'yes' }, { autostart: 1 }]) assert.throws(() => validate(bad));
  assert.equal(installScript({ url: '', sha256: '' }), null, 'no pinned download: nothing to fetch');
  assert.equal(installScript({ url: 'http://x/nordtv.gz', sha256: 'a'.repeat(64) }), null, 'https only');
  assert.equal(installScript({ url: "https://x/a';reboot;'", sha256: 'a'.repeat(64) }), null, 'no quotes in the URL');

  let tv = fakeTv({ installed: false }), v = new Vpn(tv.execute, { url: '', sha256: '' });
  let s = await v.read(true); assert.deepEqual([s.installed, s.canDownload], [false, false]);
  await assert.rejects(v.start({}), /not installed/);

  tv = fakeTv(); v = new Vpn(tv.execute);
  s = await v.start({ country: 'CH', killswitch: false }); assert.deepEqual([s.running, s.country, s.killswitch, s.publicIp], [true, 'CH', false, '198.51.100.7']);
  s = await v.stop(); assert.equal(s.running, false); assert.equal(tv.enabled, false);
  s = await v.configure({ country: 'IT' }); assert.equal(s.running, false); assert.equal(tv.country, 'IT');
  await v.start({}); const n = starts(tv);
  await v.configure({ country: 'CH' }); assert.equal(starts(tv), n + 1, 'country change reconnects a running tunnel');
  await v.configure({ autostart: false }); assert.equal(starts(tv), n + 1, 'autostart change does not');
  await assert.rejects(v.setToken('short'), /Invalid token/); await assert.rejects(v.setToken('abc; rm -rf / 0123456789'), /Invalid token/);
  s = await v.setToken(' goodtoken0123456789 '); assert.equal(tv.token, 'goodtoken0123456789'); assert.equal(s.tokenCheck.ok, true);
  assert.ok(!JSON.stringify(s).includes('goodtoken') && !tv.scripts.some(x => x.includes('goodtoken0123456789')), 'token never in clear, never returned');
  tv = fakeTv(); v = new Vpn(tv.execute); const p = v.start({}); await assert.rejects(v.stop(), /already in progress/); await p;
  assert.deepEqual(await v.countries(), [{ code: 'IT', name: 'Italy' }, { code: 'CH', name: 'Switzerland' }]);

  // supervise: only when left on + keep connected + token; never stops; backs off after a failure
  tv = fakeTv({ enabled: true }); v = new Vpn(tv.execute); assert.equal((await v.supervise()).started, true);
  for (const st of [{ enabled: false }, { autostart: false }, { hasToken: false }]) { tv = fakeTv(Object.assign({ enabled: true }, st)); v = new Vpn(tv.execute); assert.equal((await v.supervise()).started, false); }
  tv = fakeTv({ enabled: true, startFails: true }); v = new Vpn(tv.execute); await assert.rejects(v.supervise(), /HTTP 401/);
  const c = tv.scripts.length; assert.equal((await v.supervise()).started, false); assert.equal(tv.scripts.length, c, 'backs off');

  // The download step for real: a shell, a fake curl serving a local file, temporary folders for /opt/nordtv.
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'shard-vpn-')), opt = path.join(root, 'opt'), bin = path.join(root, 'bin'), served = path.join(root, 'served.gz');
  fs.mkdirSync(bin);
  fs.writeFileSync(path.join(bin, 'curl'), '#!/bin/sh\nwhile [ $# -gt 0 ]; do case "$1" in -o) out=$2; shift;; esac; shift; done\n[ -f "' + served + '" ] && cp "' + served + '" "$out"\n', { mode: 0o755 });
  if (!fs.existsSync('/usr/bin/sha256sum')) fs.writeFileSync(path.join(bin, 'sha256sum'), '#!/bin/sh\nshasum -a 256\n', { mode: 0o755 });
  const prog = v => '#!/bin/sh\necho ' + v + '\n', gz = v => zlib.gzipSync(prog(v)), sha = b => crypto.createHash('sha256').update(b).digest('hex');
  const runInstall = pin => { const script = installScript(pin).split('/opt/nordtv').join(opt); return cp.spawnSync('/bin/sh', ['-c', script], { encoding: 'utf8', env: Object.assign({}, process.env, { PATH: bin + ':' + process.env.PATH }) }).stdout; };
  fs.writeFileSync(served, gz('v1'));
  const pin1 = { url: 'https://example.invalid/nordtv.gz', sha256: sha(gz('v1')) };
  assert.ok(/__INSTALLED__/.test(runInstall(pin1))); assert.equal(fs.readFileSync(path.join(opt, 'nordtv'), 'utf8'), prog('v1'));
  assert.ok(/__CURRENT__/.test(runInstall(pin1)), 'already the pinned version: no download');
  fs.writeFileSync(served, gz('evil'));
  assert.ok(/__CHECKSUM_MISMATCH__/.test(runInstall({ url: pin1.url, sha256: sha(gz('v2')) })), 'a file with another checksum is refused');
  assert.equal(fs.readFileSync(path.join(opt, 'nordtv'), 'utf8'), prog('v1'), 'and the installed binary is kept');
  assert.ok(!fs.existsSync(path.join(opt, 'nordtv.gz.part')), 'no partial file left');
  fs.rmSync(served); assert.ok(/__DOWNLOAD_FAILED__/.test(runInstall({ url: pin1.url, sha256: sha(gz('v3')) })));
  fs.writeFileSync(served, gz('v2')); assert.ok(/__INSTALLED__/.test(runInstall({ url: pin1.url, sha256: sha(gz('v2')) })), 'a newer pinned version replaces it');
  assert.equal(fs.readFileSync(path.join(opt, 'nordtv'), 'utf8'), prog('v2'));
  fs.rmSync(root, { recursive: true, force: true });

  // Plugin lifecycle: start schedules install + supervision, stop clears them; routes.
  tv = fakeTv(); const pdir = fs.mkdtempSync(path.join(os.tmpdir(), 'shard-vpn-dir-')); fs.copyFileSync(path.join(__dirname, '../nordvpn/ui.html'), path.join(pdir, 'ui.html'));
  const inst = plugin({ id: 'nordvpn', dir: pdir, config: { get: () => ({}), set: () => {} }, execute: tv.execute });
  inst.start();
  const { Readable } = require('stream');
  const call = (method, sub, body) => new Promise(resolve => { const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]); req.method = method;
    const res = { writeHead(c) { this.code = c; }, end(b) { this.body = b; resolve(this); } }; assert.equal(inst.route(req, res, sub), true); });
  let r = await call('GET', 'ui'); assert.ok(/<title>NordVPN<\/title>/.test(r.body));
  r = await call('POST', 'action', { action: 'start', settings: { country: 'CH' } }); assert.deepEqual([r.code, JSON.parse(r.body).running], [200, true]);
  r = await call('GET', 'state'); assert.equal(JSON.parse(r.body).server, 'it455.nordvpn.com');
  r = await call('POST', 'action', { action: 'reboot' }); assert.equal(r.code, 409);
  assert.deepEqual(inst.status(), { running: true, server: 'it455.nordvpn.com', installed: true });
  inst.stop(); fs.rmSync(pdir, { recursive: true, force: true });
  console.log('PASS nordvpn plugin: settings and token validation, read-back, lock, supervision, verified download, routes');
})().catch(e => { console.error(e); process.exitCode = 1; });
