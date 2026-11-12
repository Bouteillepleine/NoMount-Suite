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
// A RECORDING bridge, not `undefined`.
//
// With no bridge at all, exec() short-circuits on its first line and returns "no webui
// env" -- so not one command string was ever built, quoted or parsed, and this gate
// exercised only the no-bridge error branch of every function. It would pass with
// `shq = (s) => s`. Recording what the page asks the shell to run lets the commands
// themselves be checked, which is the thing worth gating: these run as uid 0.
const execCalls = [];
sandbox.ksu = {
  exec(cmd, optsJson, cbName) {
    execCalls.push(String(cmd));
    try {
      JSON.parse(optsJson);
    } catch (e) {
      seen.errors.push('exec opts were not JSON: ' + optsJson);
    }
    const cb = sandbox[cbName];
    if (typeof cb === 'function') setTimeout(() => cb(0, '', ''), 0);
  },
};

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

if (typeof ctx.toast !== 'function') {
  console.error('no toast() after loading every part - the boot chain has nothing to report through');
  process.exit(1);
}
ctx.toast = (msg) => seen.errors.push('toast: ' + msg);

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
  // Every string the page handed the bridge has to be valid shell. `sh -n` parses
  // without executing, so a quoting bug -- an unbalanced quote out of shq(), a value
  // interpolated raw -- is a parse error here rather than something that runs as uid 0
  // on a device. This is what the gate was missing: it is cheap, and it fails loudly.
  if (!execCalls.length) {
    console.error('the page never asked the bridge to run anything, so nothing was checked');
    process.exit(1);
  }
  const { spawnSync } = require('child_process');

  // shq() is the only thing between a device-supplied string -- a package name, an app
  // label, a path -- and a command that runs as uid 0. Checking the commands the page
  // happens to build at boot does NOT exercise it: those values are all benign, so they
  // parse with or without quoting. Verified here by round-trip: hand the quoted form to
  // a real shell and require the exact original byte string back.
  const shq = ctx.shq;
  if (typeof shq !== 'function') {
    console.error('no shq() in scope - the shell-quoting helper is what makes exec safe');
    process.exit(1);
  }
  const NASTY = [
    "a'b", 'a b', 'a;id', 'a$(id)', 'a`id`', 'a|id', 'a&&id', 'a\nb', 'a*b', '--force',
    "';id;'", '$HOME', 'a"b', 'a\\b',
  ];
  let unsafe = 0;
  for (const raw of NASTY) {
    const r = spawnSync('sh', ['-c', 'printf %s ' + shq(raw)], { encoding: 'utf8' });
    if (r.status !== 0 || r.stdout !== raw) {
      unsafe++;
      console.error('shq() does not round-trip ' + JSON.stringify(raw) +
                    ' -> ' + JSON.stringify(shq(raw)) +
                    ' gave ' + JSON.stringify(r.stdout) + ' (status ' + r.status + ')');
    }
  }
  if (unsafe) {
    console.error(unsafe + ' of ' + NASTY.length + ' values survive shq() unquoted or mangled');
    process.exit(1);
  }

  // esc() is the same question for the DOM: an app chooses its own label, and that label
  // reaches innerHTML on a page holding the root bridge.
  // `esc` is a top-level `const`, and in a vm context those do not become properties of
  // the context object the way `function` declarations and `var` do -- they live in the
  // global lexical environment, reachable only by evaluating in the context.
  const esc = vm.runInContext('typeof esc === "function" ? esc : null', ctx);
  if (typeof esc !== 'function') {
    console.error('no esc() in scope - the HTML-escaping helper is what keeps a label inert');
    process.exit(1);
  }
  const escaped = esc('<img src=x onerror=alert(1)>&"\'');
  // The four that open a tag or close an attribute must be gone outright. `&` cannot be
  // checked that way -- escaping PRODUCES it, as the first character of every entity --
  // so instead require that nothing is left once the known entities are removed.
  for (const ch of ['<', '>', '"', "'"]) {
    if (escaped.includes(ch)) {
      console.error('esc() leaves ' + JSON.stringify(ch) + ' raw: ' + JSON.stringify(escaped));
      process.exit(1);
    }
  }
  if (escaped.replace(/&(amp|lt|gt|quot|#39);/g, '').includes('&')) {
    console.error('esc() leaves a bare & behind: ' + JSON.stringify(escaped));
    process.exit(1);
  }

  let bad = 0;
  for (const cmd of execCalls) {
    const r = spawnSync('sh', ['-n', '-c', cmd], { encoding: 'utf8' });
    if (r.status !== 0) {
      bad++;
      console.error('not valid shell: ' + JSON.stringify(cmd));
      console.error('  ' + String(r.stderr || '').trim().split('\n')[0]);
    }
  }
  if (bad) {
    console.error(bad + ' of ' + execCalls.length + ' command(s) the page built do not parse');
    process.exit(1);
  }
  console.log('load order OK across ' + srcs.length + ' parts');
  console.log(execCalls.length + ' built command(s) parse as shell');
})();
