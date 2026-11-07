'use strict';
// Shell: runs one command at a time on the TV as root (ctx.execute, the same path as Vetro's own commands).
// Each command gets a fresh shell, so only the working directory is carried over: the command runs in the cwd the
// page sends, and the cwd it ends in comes back after a marker line with a per-request nonce (a command cannot
// fake it). bash is used when the TV has it, sh otherwise. stdin is /dev/null so a command waiting for input ends
// instead of holding Vetro's command queue until the time limit. Plain ES5: older TVs run Node 4.4.
var crypto = require('crypto'), fs = require('fs'), path = require('path');
var DEFAULT_TIMEOUT = 30000, MAX_TIMEOUT = 120000, MAX_COMMAND = 16384, MAX_OUTPUT = 262144, MAX_HISTORY = 200, MAX_BODY = 32768;

function quote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function validCwd(cwd) { return typeof cwd === 'string' && cwd.charAt(0) === '/' && cwd.length <= 4096 && !/[\0\n\r]/.test(cwd); }

function build(p) {
    p = p || {};
    var cmd = p.cmd, cwd = p.cwd == null ? '/' : p.cwd, timeout = p.timeout == null ? DEFAULT_TIMEOUT : p.timeout;
    if (typeof cmd !== 'string' || !cmd.trim()) throw new Error('Missing command');
    if (cmd.length > MAX_COMMAND) throw new Error('Command too long');
    if (!validCwd(cwd)) throw new Error('Invalid working directory');
    if (typeof timeout !== 'number' || !(timeout >= 1000) || timeout > MAX_TIMEOUT) throw new Error('Time limit must be 1–120 seconds');
    var nonce = crypto.randomBytes(8).toString('hex'), marker = '__VETRO_CWD_' + nonce + '__';
    var shown = cwd.replace(/[^\x20-\x7e]/g, '?').replace(/["$`\\]/g, '?');
    var script = 'cd ' + quote(cwd) + ' 2>/dev/null || { echo "cd: ' + shown + ': not found, using /" >&2; cd /; }\n' +
        cmd + '\n__vetro_status=$?\nprintf "\\n' + marker + '%s\\n" "$(pwd)"\nexit $__vetro_status\n';
    var b64 = Buffer.from(script).toString('base64');
    var command = '__vetro_script="$(echo ' + b64 + ' | base64 -d)"; if command -v bash >/dev/null 2>&1; then exec bash -c "$__vetro_script" </dev/null; else exec sh -c "$__vetro_script" </dev/null; fi';
    return { command: command, nonce: nonce, timeout: Math.round(timeout), cwd: cwd };
}

function cap(s) { s = String(s || ''); return s.length > MAX_OUTPUT ? { text: s.slice(0, MAX_OUTPUT), truncated: true } : { text: s, truncated: false }; }

function parse(r, job) {
    r = r || {};
    var out = String(r.stdout || ''), marker = '\n__VETRO_CWD_' + job.nonce + '__', i = out.lastIndexOf(marker), cwd = job.cwd;
    if (i >= 0) {
        var rest = out.slice(i + marker.length), nl = rest.indexOf('\n'), found = nl < 0 ? rest : rest.slice(0, nl);
        if (validCwd(found)) cwd = found;
        out = out.slice(0, i) + rest.slice(nl < 0 ? rest.length : nl + 1);
    }
    var so = cap(out), se = cap(r.stderr);
    return { ok: r.exit_code === 0 && !r.timed_out, exit_code: r.exit_code, timed_out: !!r.timed_out, stdout: so.text, stderr: se.text, truncated: so.truncated || se.truncated, cwd: cwd };
}

function run(execute, p) {
    var job;
    try { job = build(p); } catch (e) { return Promise.reject(e); }
    return execute(job.command, job.timeout).then(function (r) { return parse(r, job); });
}

function json(res, body, code) {
    res.writeHead(code || 200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
}
function readJson(req, cb) {
    var chunks = [], size = 0, done = false;
    req.on('data', function (c) { size += c.length; if (size > MAX_BODY) { if (!done) { done = true; cb(new Error('Request too large')); } req.destroy && req.destroy(); return; } chunks.push(c); });
    req.on('end', function () { if (done) return; done = true; var p; try { p = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); } catch (e) { return cb(new Error('Invalid JSON')); } if (!p || typeof p !== 'object' || Array.isArray(p)) return cb(new Error('Invalid JSON')); cb(null, p); });
    req.on('error', function (e) { if (!done) { done = true; cb(e); } });
}

module.exports = function (ctx) {
    var page = null, busy = false, runs = 0, lastCwd = '/';
    function history() { var h = ctx.config.get().history; return Array.isArray(h) ? h.filter(function (x) { return typeof x === 'string'; }) : []; }
    function remember(cmd, cwd) {
        var c = ctx.config.get(), h = history();
        if (h[h.length - 1] !== cmd) h.push(cmd);
        c.history = h.slice(-MAX_HISTORY); c.cwd = cwd;
        try { ctx.config.set(c); } catch (e) { /* history is a convenience */ }
    }
    return {
        start: function () { page = fs.readFileSync(path.join(ctx.dir, 'ui.html'), 'utf8'); lastCwd = validCwd(ctx.config.get().cwd) ? ctx.config.get().cwd : '/'; },
        stop: function () { page = null; },
        status: function () { return { commands: runs, cwd: lastCwd, running: busy }; },
        route: function (req, res, sub) {
            if (sub === 'ui' && req.method === 'GET') {
                res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
                res.end(page || '');
                return true;
            }
            if (sub === 'state' && req.method === 'GET') { json(res, { cwd: lastCwd, history: history(), busy: busy }); return true; }
            if (sub === 'history' && req.method === 'DELETE') { var c = ctx.config.get(); c.history = []; ctx.config.set(c); json(res, { ok: true }); return true; }
            if (sub === 'run' && req.method === 'POST') {
                readJson(req, function (err, p) {
                    if (err) return json(res, { ok: false, error: err.message }, 400);
                    if (busy) return json(res, { ok: false, error: 'A command is already running' }, 409);
                    try { build(p); } catch (e) { return json(res, { ok: false, error: e.message }, 400); }
                    busy = true;
                    run(ctx.execute, p).then(function (d) {
                        runs++; lastCwd = d.cwd; remember(p.cmd, d.cwd); json(res, d);
                    }, function (e) {
                        json(res, { ok: false, error: String(e && e.message || e) }, 503);
                    }).then(function () { busy = false; }, function () { busy = false; });
                });
                return true;
            }
            return false;
        }
    };
};
module.exports.build = build;
module.exports.parse = parse;
module.exports.run = run;
