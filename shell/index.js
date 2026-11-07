'use strict';
// Shell: runs one command at a time on the TV as root (ctx.execute, the same path as Vetro's own commands).
// Each command gets a fresh shell, so only the working directory is carried over: the command runs in the cwd the
// page sends, and the cwd it ends in comes back after a marker line with a per-request nonce (a command cannot
// fake it). bash is used when the TV has it, sh otherwise. stdin is /dev/null so a command waiting for input ends
// instead of holding Vetro's command queue until the time limit. Plain ES5: older TVs run Node 4.4.
var crypto = require('crypto'), fs = require('fs'), path = require('path');
// Every Vetro TV command shares one queue: a long command makes everything else wait, so the cap is 60 s.
var DEFAULT_TIMEOUT = 30000, MAX_TIMEOUT = 60000, MAX_COMMAND = 16384, MAX_OUTPUT = 262144, MAX_HISTORY = 200, MAX_BODY = 32768;

// Node 4.4 has a Buffer.from inherited from Uint8Array that does not take a string; Node 5.10+ has the real one.
function bytes(s) { return Buffer.from && Buffer.from !== Uint8Array.from ? Buffer.from(s) : new Buffer(s); }
function quote(s) { return "'" + String(s).replace(/'/g, "'\\''") + "'"; }
function validCwd(cwd) { return typeof cwd === 'string' && cwd.charAt(0) === '/' && cwd.length <= 4096 && !/[\0\n\r]/.test(cwd); }

function build(p) {
    p = p || {};
    var cmd = p.cmd, cwd = p.cwd == null ? '/' : p.cwd, timeout = p.timeout == null ? DEFAULT_TIMEOUT : p.timeout;
    if (typeof cmd !== 'string' || !cmd.trim()) throw new Error('Missing command');
    if (cmd.length > MAX_COMMAND) throw new Error('Command too long');
    if (!validCwd(cwd)) throw new Error('Invalid working directory');
    if (typeof timeout !== 'number' || !(timeout >= 1000) || timeout > MAX_TIMEOUT) throw new Error('Time limit must be 1–60 seconds');
    var nonce = crypto.randomBytes(8).toString('hex'), marker = '__VETRO_CWD_' + nonce + '__';
    var shown = cwd.replace(/[^\x20-\x7e]/g, '?').replace(/["$`\\]/g, '?');
    var script = 'cd ' + quote(cwd) + ' 2>/dev/null || { echo "cd: ' + shown + ': not found, using /" >&2; cd /; }\n' +
        cmd + '\n__vetro_status=$?\nprintf "\\n' + marker + '%s\\n" "$(pwd)"\nexit $__vetro_status\n';
    var b64 = bytes(script).toString('base64');
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

// The page ships next to this file. ctx.dir is the plugin's folder on the TV, but a test harness may give an empty
// one: read it from where the code is, fall back to ctx.dir, and never fail start() over it.
function loadPage(ctx) {
    var places = [path.join(__dirname, 'ui.html'), path.join(ctx.dir || '', 'ui.html')];
    for (var i = 0; i < places.length; i++) { try { return fs.readFileSync(places[i], 'utf8'); } catch (e) { /* next */ } }
    return '<!doctype html><meta charset="utf-8"><p>Page file missing: reinstall this Shard.</p>';
}
module.exports = function (ctx) {
    var page = null, busy = false, runs = 0, lastCwd = '/';
    // config.json: { saveHistory: boolean (default true), history: [commands], cwd }. Commands can hold secrets typed
    // on the command line, so history can be cleared from the page and switched off; off also deletes what was saved.
    // A config read or write that fails never breaks a request: history is a convenience.
    function load() { try { var c = ctx.config.get(); return c && typeof c === 'object' && !Array.isArray(c) ? c : {}; } catch (e) { return {}; } }
    function save(c) { try { ctx.config.set(c); return true; } catch (e) { return false; } }
    function saving(c) { return (c || load()).saveHistory !== false; }
    function history(c) { c = c || load(); var h = c.history; return saving(c) && Array.isArray(h) ? h.filter(function (x) { return typeof x === 'string'; }) : []; }
    function remember(cmd, cwd) {
        var c = load(), h = history(c);
        if (saving(c) && h[h.length - 1] !== cmd) h.push(cmd);
        c.history = saving(c) ? h.slice(-MAX_HISTORY) : [];
        c.cwd = cwd;
        save(c);
    }
    function clearHistory() { var c = load(); c.history = []; return save(c); }
    function state() { var c = load(); return { cwd: lastCwd, history: history(c), saveHistory: saving(c), busy: busy }; }
    return {
        start: function () { var c = load(); page = loadPage(ctx); lastCwd = validCwd(c.cwd) ? c.cwd : '/'; },
        stop: function () { page = null; },
        status: function () { return { commands: runs, cwd: lastCwd, running: busy }; },
        route: function (req, res, sub) {
            if (sub === 'ui' && req.method === 'GET') {
                res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
                res.end(page || '');
                return true;
            }
            if (sub === 'state' && req.method === 'GET') { json(res, state()); return true; }
            // POST: the sandboxed page may only send GET and POST (the host's CORS preflight allows nothing else).
            if (sub === 'history/clear' && (req.method === 'POST' || req.method === 'DELETE')) {
                if (clearHistory()) json(res, state()); else json(res, { ok: false, error: 'History could not be cleared' }, 500);
                return true;
            }
            if (sub === 'settings' && req.method === 'POST') {
                readJson(req, function (err, p) {
                    if (err) return json(res, { ok: false, error: err.message }, 400);
                    if (typeof p.saveHistory !== 'boolean') return json(res, { ok: false, error: 'saveHistory must be true or false' }, 400);
                    var c = load(); c.saveHistory = p.saveHistory; if (!p.saveHistory) c.history = [];
                    if (!save(c)) return json(res, { ok: false, error: 'Setting could not be saved' }, 500);
                    json(res, state());
                });
                return true;
            }
            if (sub === 'run' && req.method === 'POST') {
                readJson(req, function (err, p) {
                    if (err) return json(res, { ok: false, error: err.message }, 400);
                    if (busy) return json(res, { ok: false, error: 'A command is already running' }, 409);
                    try { build(p); } catch (e) { return json(res, { ok: false, error: e.message }, 400); }
                    busy = true;
                    run(ctx.execute, p).then(function (d) {
                        runs++; lastCwd = d.cwd;
                        try { remember(p.cmd, d.cwd); } catch (e) { /* the command ran: answer anyway */ }
                        json(res, d);
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
