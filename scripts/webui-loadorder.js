const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = process.argv[2] || path.join(__dirname, '..');
const WEBROOT = path.join(ROOT, 'module', 'webroot');
const html = fs.readFileSync(path.join(WEBROOT, 'index.html'), 'utf8');
const srcs = [...html.matchAll(/<script src="([^"]+)"><\/script>/g)].map((m) => m[1]);
if (!srcs.length) {
  console.error('no <script src> found in index.html');
  process.exit(1);
}

const seen = { errors: [] };
const swallow = () => absorber;
const absorber = new Proxy(function () {}, {
  get(_t, prop) {
    if (prop === Symbol.toPrimitive || prop === 'toString') return () => '';
    if (prop === Symbol.iterator) return function* () {};
    if (prop === 'length') return 0;
    if (prop === 'classList') return absorber;
    if (prop === 'style') return absorber;
    return absorber;
  },
  set() { return true; },
  apply: swallow,
  construct: swallow,
  has() { return true; },
});

const storage = {
  getItem: () => null, setItem: () => {}, removeItem: () => {}, clear: () => {},
};

const sandbox = {
  console,
  setTimeout,
  clearTimeout,
  Promise,
  JSON,
  Math,
  Date,
  localStorage: storage,
  sessionStorage: storage,
  navigator: { clipboard: { writeText: () => Promise.resolve() }, userAgent: 'node' },
  location: { href: '', search: '', hash: '' },
  matchMedia: () => ({ matches: false, addEventListener: () => {}, addListener: () => {} }),
  requestAnimationFrame: (fn) => setTimeout(fn, 0),
  document: new Proxy({}, {
    get(_t, prop) {
      if (prop === 'getElementById' || prop === 'querySelector') return () => absorber;
      if (prop === 'querySelectorAll' || prop === 'getElementsByClassName') return () => [];
      if (prop === 'createElement') return () => absorber;
      if (prop === 'addEventListener') return () => {};
      if (prop === 'documentElement' || prop === 'body' || prop === 'head') return absorber;
      return absorber;
    },
    set() { return true; },
  }),
};
sandbox.window = sandbox;
sandbox.globalThis = sandbox;
sandbox.window.addEventListener = () => {};
sandbox.ksu = undefined; // no root manager, exactly what a desktop browser is

const ctx = vm.createContext(sandbox);
process.on('unhandledRejection', (e) => seen.errors.push('unhandledRejection: ' + e));

for (const rel of srcs) {
  const file = path.join(WEBROOT, rel.split('/').join(path.sep));
  const code = fs.readFileSync(file, 'utf8');
  try {
    new vm.Script(code, { filename: rel }).runInContext(ctx);
  } catch (e) {
    console.error('THREW while loading ' + rel + ': ' + (e && e.message));
    if (e instanceof ReferenceError) {
      console.error('  -> a part reads a binding declared in a LATER part; reorder them');
    }
    process.exit(1);
  }
  console.log('  loaded ' + rel);
}

// The boot chain in 60-boot.js is asynchronous, so a ReferenceError inside it
// surfaces as an unhandledRejection on a LATER tick. Reading seen.errors in the
// same tick as the last runInContext made this filter dead code: it always saw
// an empty array. Give the loop turns to run, then judge.
const tick = () => new Promise((r) => setTimeout(r, 0));

(async () => {
  for (let i = 0; i < 20; i++) {
    await tick();
  }
  const refErrs = seen.errors.filter((e) =>
    /is not defined|before initialization/.test(e));
  if (refErrs.length) {
    console.error('async load-order errors:');
    for (const e of refErrs) {
      console.error('  ' + e);
    }
    process.exit(1);
  }
  console.log('load order OK across ' + srcs.length + ' parts');
})();
