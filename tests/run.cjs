'use strict';
// Runs every *.test.cjs here. host.test.cjs needs a Vetro checkout: VETRO_DIR (default ../vetro, then ../vetro-0.5.0).
const fs = require('fs'), path = require('path'), spawnSync = require('child_process').spawnSync;
const tests = fs.readdirSync(__dirname).filter(n => n.endsWith('.test.cjs')).sort();
for (const name of tests) {
  console.log('\n' + name);
  const r = spawnSync(process.execPath, [path.join(__dirname, name)], { stdio: 'inherit', timeout: 60000 });
  if (r.error || r.status !== 0) { if (r.error) console.error(r.error.message); process.exit(1); }
}
console.log('\nPASS ' + tests.length + ' test suites');
