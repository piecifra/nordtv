'use strict';
// NordVPN (NordLynx) on the TV through nordtv, the WireGuard client built from ../nordtv (nordtv/build.sh).
// A plugin bundle is text only, so the 2.8 MB binary is not inside it:
//  - /opt/nordtv/nordtv is used when it is there (installed by hand, or by an earlier version).
//  - When it is missing, or was installed by an older plugin version, the plugin downloads BINARY.url, refuses it
//    unless its SHA-256 is BINARY.sha256, unpacks it and records the checksum in /opt/nordtv/.source. This runs at
//    start and from the page, never on every call, so a slow download cannot hold Vetro's command queue.
//  - Before each command it is copied to /dev/shm, where the TV lets it run (also after every boot).
// State lives in the binary's own files (/opt/nordtv/config, token, log); the same commands work from a shell.
// The token is written through base64 and never read back. Plain ES5: older TVs run Node 4.4.
var fs = require('fs'), path = require('path');
var BINARY = { url: '', sha256: '' };   // filled in by nordtv/build.sh --pin (see README)
var DIR = '/opt/nordtv', RUN = '/dev/shm/nordtv';
var COUNTRY = /^[A-Z]{2}$/, TOKEN = /^[A-Za-z0-9_-]{16,256}$/, SHA = /^[0-9a-f]{64}$/, URL_RE = /^https:\/\/[A-Za-z0-9.\/_~%+-]+$/;
var RETRY_MS = 120000, TICK_MS = 60000, FIRST_TICK_MS = 15000, MAX_BODY = 8192;

// /opt/nordtv holds a binary that runs as root: only root may change it (the TV's default umask left it 0777).
var STAGE = 'chmod 755 ' + DIR + ' 2>/dev/null; chmod go-w ' + DIR + '/* 2>/dev/null; chmod 600 ' + DIR + '/token 2>/dev/null\n' +
    '[ -x ' + DIR + '/nordtv ] || { echo __NOBIN__; exit 0; }\n' +
    'a=$(md5sum < ' + DIR + '/nordtv); b=$(md5sum < ' + RUN + ' 2>/dev/null)\n' +
    'if [ "$a" != "$b" ]; then cp ' + DIR + '/nordtv ' + RUN + '.new && chmod 755 ' + RUN + '.new && mv -f ' + RUN + '.new ' + RUN + '; fi\ncd /\n';

// Node 4.4 has a Buffer.from inherited from Uint8Array that does not take a string; Node 5.10+ has the real one.
function bytes(s) { return Buffer.from && Buffer.from !== Uint8Array.from ? Buffer.from(s) : new Buffer(s); }
function installScript(bin) {
    if (!bin || !URL_RE.test(bin.url || '') || !SHA.test(bin.sha256 || '')) return null;
    var tmp = DIR + '/nordtv.gz.part';
    return 'umask 022\nmkdir -p ' + DIR + ' && chmod 755 ' + DIR + '\n' +
        'if [ -x ' + DIR + '/nordtv ] && [ "$(cat ' + DIR + '/.source 2>/dev/null)" = ' + bin.sha256 + ' ]; then echo __CURRENT__; exit 0; fi\n' +
        'rm -f ' + tmp + '\n' +
        'curl -fsSL --max-time 90 -o ' + tmp + ' \'' + bin.url + '\' || { rm -f ' + tmp + '; echo __DOWNLOAD_FAILED__; exit 0; }\n' +
        'if [ "$(sha256sum < ' + tmp + ' | cut -d" " -f1)" != ' + bin.sha256 + ' ]; then rm -f ' + tmp + '; echo __CHECKSUM_MISMATCH__; exit 0; fi\n' +
        'gunzip -c ' + tmp + ' > ' + DIR + '/nordtv.new && chmod 755 ' + DIR + '/nordtv.new && mv -f ' + DIR + '/nordtv.new ' + DIR + '/nordtv && echo ' + bin.sha256 + ' > ' + DIR + '/.source && rm -f ' + tmp + ' && echo __INSTALLED__\n';
}

function wrap(s) { return 'echo ' + bytes(s).toString('base64') + ' | base64 -d | sh'; }
function lastJson(out) {
    var lines = String(out || '').trim().split('\n');
    for (var i = lines.length - 1; i >= 0; i--) { var l = lines[i].trim(); if (l.charAt(0) === '{') { try { return JSON.parse(l); } catch (e) { /* not JSON */ } } }
    return null;
}
function failure(r, fallback) {
    var text = String(r && (r.stderr || r.stdout) || '').trim().split('\n').filter(function (l) { return l && l.indexOf('sendmmsg') < 0; }).slice(-3).join(' · ');
    return new Error(text || fallback);
}
function validate(o) {
    o = o || {}; var out = {};
    if (o.country !== undefined) { if (o.country !== '' && !COUNTRY.test(o.country)) throw new Error('Invalid country code'); out.country = o.country; }
    ['killswitch', 'autostart'].forEach(function (k) { if (o[k] !== undefined) { if (typeof o[k] !== 'boolean') throw new Error('Invalid ' + k); out[k] = o[k]; } });
    return out;
}
function settingsScript(o) {
    var s = '';
    if (o.country !== undefined) s += RUN + ' set country "' + o.country + '" >/dev/null\n';
    if (o.killswitch !== undefined) s += RUN + ' set killswitch ' + (o.killswitch ? 'on' : 'off') + ' >/dev/null\n';
    if (o.autostart !== undefined) s += RUN + ' set autostart ' + (o.autostart ? 'on' : 'off') + ' >/dev/null\n';
    return s;
}

function Vpn(execute, bin) { this.execute = execute; this.bin = bin || BINARY; this.busy = false; this.countryList = null; this.autoFailedAt = 0; this.lastAuto = null; this.lastInstall = null; this.last = null; }
function lock(self, work) {
    if (self.busy) return Promise.reject(new Error('VPN change already in progress'));
    self.busy = true;
    return Promise.resolve().then(work).then(function (v) { self.busy = false; return v; }, function (e) { self.busy = false; throw e; });
}
Vpn.prototype.install = function () {
    var self = this, script = installScript(this.bin);
    if (!script) { this.lastInstall = { at: Date.now(), result: 'no-download' }; return Promise.resolve(this.lastInstall); }
    return this.execute(wrap(script), 120000).then(function (r) {
        var m = /__(CURRENT|INSTALLED|DOWNLOAD_FAILED|CHECKSUM_MISMATCH)__/.exec(r.stdout || '');
        self.lastInstall = { at: Date.now(), result: m ? m[1].toLowerCase().replace('_', '-') : 'failed' };
        if (!m) self.lastInstall.error = failure(r, 'Install failed').message;
        return self.lastInstall;
    });
};
Vpn.prototype.read = function (withIp) {
    var self = this;
    return this.execute(wrap(STAGE + RUN + ' ' + (withIp ? 'status -json' : 'state')), withIp ? 20000 : 10000).then(function (r) {
        if (/__NOBIN__/.test(r.stdout || '')) return (self.last = { installed: false, canDownload: !!installScript(self.bin), lastInstall: self.lastInstall });
        var s = lastJson(r.stdout); if (!s) throw failure(r, 'VPN state unreadable');
        s.installed = true; s.lastAuto = self.lastAuto; s.lastInstall = self.lastInstall; s.canDownload = !!installScript(self.bin);
        return (self.last = s);
    });
};
Vpn.prototype.countries = function () {
    var self = this;
    if (this.countryList) return Promise.resolve(this.countryList);
    return this.execute(wrap(STAGE + RUN + ' countries'), 25000).then(function (r) {
        if (/__NOBIN__/.test(r.stdout || '')) throw new Error('The VPN program is not installed');
        var list = String(r.stdout || '').split('\n').map(function (l) { var p = l.split('\t'); return p.length === 2 && COUNTRY.test(p[0]) ? { code: p[0], name: p[1].trim() } : null; }).filter(Boolean);
        if (!list.length) throw failure(r, 'Country list unavailable');
        return (self.countryList = list);
    });
};
Vpn.prototype.start = function (opts) {
    var self = this, o;
    try { o = validate(opts); } catch (e) { return Promise.reject(e); }
    return lock(this, function () {
        return self.execute(wrap(STAGE + settingsScript(o) + RUN + ' start 2>&1'), 90000).then(function (r) {
            if (/__NOBIN__/.test(r.stdout || '')) throw new Error('The VPN program is not installed');
            return self.read(true).then(function (s) {
                if (!s.running) throw failure(r, 'VPN did not start');
                if (o.country !== undefined && s.country !== o.country) throw new Error('Country not confirmed');
                if (o.killswitch !== undefined && s.killswitch !== o.killswitch) throw new Error('Kill switch not confirmed');
                return s;
            });
        });
    });
};
Vpn.prototype.stop = function () {
    var self = this;
    return lock(this, function () {
        return self.execute(wrap(STAGE + RUN + ' stop 2>&1'), 30000).then(function () { return self.read(false); }).then(function (s) {
            if (s.running) throw new Error('VPN still running');
            return s;
        });
    });
};
Vpn.prototype.configure = function (opts) {
    var self = this, o;
    try { o = validate(opts); } catch (e) { return Promise.reject(e); }
    return this.read(false).then(function (s) {
        if (!s.installed) throw new Error('The VPN program is not installed');
        var restart = s.running && (o.country !== undefined && o.country !== s.country || o.killswitch !== undefined && o.killswitch !== s.killswitch);
        if (restart) return self.start(o);
        return lock(self, function () { return self.execute(wrap(STAGE + settingsScript(o)), 15000).then(function () { return self.read(false); }); });
    });
};
Vpn.prototype.setToken = function (token) {
    var self = this;
    if (typeof token !== 'string' || !TOKEN.test(token.trim())) return Promise.reject(new Error('Invalid token format'));
    var b64 = bytes(token.trim() + '\n').toString('base64');
    return lock(this, function () {
        return self.execute(wrap(STAGE + 'umask 077\nmkdir -p ' + DIR + '\necho ' + b64 + ' | base64 -d > ' + DIR + '/token.new && mv -f ' + DIR + '/token.new ' + DIR + '/token\n' + RUN + ' verify'), 30000).then(function (r) {
            if (/__NOBIN__/.test(r.stdout || '')) throw new Error('The VPN program is not installed');
            var v = lastJson(r.stdout); if (!v) throw failure(r, 'Token check unavailable');
            return self.read(false).then(function (s) { s.tokenCheck = v; return s; });
        });
    });
};
// Starts the tunnel only when it was left on (enabled) with "keep connected" (autostart) and a token. Never stops it.
Vpn.prototype.supervise = function () {
    var self = this;
    if (this.busy || Date.now() - this.autoFailedAt < RETRY_MS) return Promise.resolve({ started: false });
    return this.read(false).then(function (s) {
        if (!s.installed || s.running || !s.enabled || !s.autostart || !s.hasToken) return { started: false };
        return self.start({}).then(function (after) { self.lastAuto = { at: Date.now(), ok: true }; return { started: true, state: after }; },
            function (e) { self.autoFailedAt = Date.now(); self.lastAuto = { at: Date.now(), ok: false, error: e.message }; throw e; });
    });
};

function json(res, body, code) {
    res.writeHead(code || 200, { 'content-type': 'application/json', 'cache-control': 'no-store' });
    res.end(JSON.stringify(body));
}
function readJson(req, cb) {
    var chunks = [], size = 0, done = false;
    req.on('data', function (c) { size += c.length; if (size > MAX_BODY) { if (!done) { done = true; cb(new Error('Request too large')); } return; } chunks.push(c); });
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
    var vpn = new Vpn(ctx.execute), page = null, timer = null, first = null, stopped = true;
    function tick() { if (stopped) return; vpn.supervise().catch(function () { /* recorded in lastAuto; the root agent may not be up yet */ }); }
    function reply(res, p) { p.then(function (d) { json(res, d); }, function (e) { json(res, { ok: false, error: String(e && e.message || e) }, 409); }); }
    return {
        start: function () {
            stopped = false;
            page = loadPage(ctx);
            // Install (or update) the binary first, then begin supervising; neither may throw out of start().
            first = setTimeout(function () { vpn.install().catch(function () {}).then(tick); }, FIRST_TICK_MS);
            timer = setInterval(tick, TICK_MS);
            if (timer.unref) timer.unref();
        },
        stop: function () { stopped = true; clearTimeout(first); clearInterval(timer); page = null; },
        status: function () { var s = vpn.last || {}; return { running: !!s.running, server: s.server || null, installed: s.installed !== false }; },
        route: function (req, res, sub) {
            if (sub === 'ui' && req.method === 'GET') { res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' }); res.end(page || ''); return true; }
            if (sub === 'state' && req.method === 'GET') { reply(res, vpn.read(true)); return true; }
            if (sub === 'countries' && req.method === 'GET') { reply(res, vpn.countries().then(function (c) { return { countries: c }; })); return true; }
            if (sub === 'action' && req.method === 'POST') {
                readJson(req, function (err, p) {
                    if (err) return json(res, { ok: false, error: err.message }, 400);
                    var t = p.action === 'start' ? vpn.start(p.settings) : p.action === 'stop' ? vpn.stop() : p.action === 'configure' ? vpn.configure(p.settings)
                        : p.action === 'token' ? vpn.setToken(p.token) : p.action === 'install' ? vpn.install().then(function () { return vpn.read(false); })
                        : Promise.reject(new Error('Invalid VPN action'));
                    reply(res, t);
                });
                return true;
            }
            return false;
        }
    };
};
module.exports.Vpn = Vpn;
module.exports.validate = validate;
module.exports.installScript = installScript;
module.exports.STAGE = STAGE;
module.exports.BINARY = BINARY;
