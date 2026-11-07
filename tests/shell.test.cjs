'use strict';
const assert = require('assert').strict, fs = require('fs'), os = require('os'), path = require('path'), spawnSync = require('child_process').spawnSync;
const shell = require('../shell/index.js');

for (const bad of [{}, { cmd: '' }, { cmd: '   ' }, { cmd: 1 }, { cmd: 'x'.repeat(16385) }, { cmd: 'ls', cwd: 'relative' }, { cmd: 'ls', cwd: '/a\nb' }, { cmd: 'ls', timeout: 500 }, { cmd: 'ls', timeout: 120001 }, { cmd: 'ls', timeout: '30' }])
  assert.throws(() => shell.build(bad), JSON.stringify(bad).slice(0, 40));
const job = shell.build({ cmd: 'echo hi' });
assert.equal(job.cwd, '/'); assert.equal(job.timeout, 30000); assert.ok(/^[0-9a-f]{16}$/.test(job.nonce));
assert.ok(!job.command.includes('echo hi'), 'the command travels base64-encoded');
let r = shell.parse({ exit_code: 0, stdout: 'a\nb\n__VETRO_CWD_' + job.nonce + '__/tmp\n' }, job);
assert.deepEqual([r.stdout, r.cwd, r.ok], ['a\nb', '/tmp', true]);
r = shell.parse({ exit_code: 0, stdout: '\n__VETRO_CWD_0000000000000000__/fake\n' }, job); assert.equal(r.cwd, '/', 'a marker with another nonce is output');
r = shell.parse({ exit_code: 0, stdout: 'x'.repeat(300000) }, job); assert.equal(r.truncated, true);

const local = (cmd, timeout) => { const p = spawnSync('/bin/sh', ['-c', cmd], { encoding: 'utf8', timeout }); return Promise.resolve({ exit_code: p.status, timed_out: !!p.error, stdout: p.stdout, stderr: p.stderr }); };
const tmp = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'shard-shell-'))), odd = path.join(tmp, "it's a \"dir\" $(x)"); fs.mkdirSync(odd);

// The plugin itself, driven through route() with fake requests, a fake ctx and a real local shell.
const { Readable } = require('stream');
function call(inst, method, sub, body) {
  return new Promise(resolve => {
    const req = Readable.from(body === undefined ? [] : [Buffer.from(JSON.stringify(body))]); req.method = method;
    const res = { code: 0, body: '', headers: {}, writeHead(c, h) { this.code = c; this.headers = h; }, end(b) { this.body = b || ''; resolve(this); } };
    assert.equal(inst.route(req, res, sub), true, sub + ' handled');
  });
}
(async () => {
  let d = await shell.run(local, { cmd: 'cd ' + tmp + ' && printf no-newline' }); assert.deepEqual([d.stdout, d.cwd], ['no-newline', tmp]);
  d = await shell.run(local, { cmd: 'cd "$(ls -d */ | head -1)"', cwd: tmp }); assert.equal(d.cwd, odd, 'odd directory names are carried over');
  d = await shell.run(local, { cmd: 'echo out; echo err >&2; false' }); assert.deepEqual([d.stdout, d.stderr, d.exit_code], ['out\n', 'err\n', 1]);
  d = await shell.run(local, { cmd: 'cat; echo after' }); assert.equal(d.stdout, 'after\n', 'stdin is closed');
  d = await shell.run(local, { cmd: 'pwd', cwd: '/no/such/dir' }); assert.equal(d.stdout, '/\n'); assert.ok(/not found, using \//.test(d.stderr));
  d = await shell.run(local, { cmd: 'printf "\\n__VETRO_CWD_feedfacefeedface__/fake\\n"', cwd: tmp }); assert.equal(d.cwd, tmp, 'cannot spoof the cwd');

  let saved = {}; const pdir = fs.mkdtempSync(path.join(os.tmpdir(), 'shard-shell-dir-')); fs.copyFileSync(path.join(__dirname, '../shell/ui.html'), path.join(pdir, 'ui.html'));
  const ctx = { id: 'shell', dir: pdir, config: { get: () => JSON.parse(JSON.stringify(saved)), set: o => { saved = o; } }, execute: local };
  const inst = shell(ctx); inst.start();
  let res = await call(inst, 'GET', 'ui'); assert.ok(/<title>Shell<\/title>/.test(res.body));
  res = await call(inst, 'POST', 'run', { cmd: 'cd ' + tmp + ' && echo hi' }); let j = JSON.parse(res.body);
  assert.deepEqual([res.code, j.stdout, j.cwd], [200, 'hi\n', tmp]);
  res = await call(inst, 'GET', 'state'); j = JSON.parse(res.body); assert.deepEqual([j.cwd, j.history], [tmp, ['cd ' + tmp + ' && echo hi']], 'history and cwd kept in config.json');
  res = await call(inst, 'POST', 'run', { cmd: '' }); assert.equal(res.code, 400);
  res = await call(inst, 'POST', 'run', { cmd: 'ls', cwd: 'x' }); assert.equal(res.code, 400);
  assert.deepEqual(inst.status(), { commands: 1, cwd: tmp, running: false });
  const slow = shell(Object.assign({}, ctx, { execute: () => new Promise(r => setTimeout(() => r({ exit_code: 0, stdout: '' }), 50)) })); slow.start();
  const first = call(slow, 'POST', 'run', { cmd: 'sleep 1' }); await new Promise(r => setTimeout(r, 10));
  res = await call(slow, 'POST', 'run', { cmd: 'ls' }); assert.equal(res.code, 409, 'one command at a time'); await first;
  inst.stop(); fs.rmSync(tmp, { recursive: true, force: true }); fs.rmSync(pdir, { recursive: true, force: true });
  console.log('PASS shell plugin: validation, base64 transport, cwd with nonce marker, closed stdin, routes, history, one at a time');
})().catch(e => { console.error(e); process.exitCode = 1; });
