// The hand-written .d.mts declarations must cover every runtime export of every
// public entry point, or a TypeScript consumer silently loses part of the API
// (or gets an import error) the day someone adds an export and forgets the types.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), '..');
const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));

// Names a .d.mts file makes available as values: `export declare const|function|class X`
// and `export { A, B }` re-exports.
function declaredValues(file) {
  const src = fs.readFileSync(file, 'utf8');
  const names = new Set();
  for (const m of src.matchAll(/^export declare (?:const|function|class) (\w+)/gm)) names.add(m[1]);
  for (const m of src.matchAll(/^export \{([^}]+)\}/gm)) for (const n of m[1].split(',')) names.add(n.trim().split(/\s+as\s+/).pop());
  return names;
}

test('package.json points "types" at the main entry declarations', () => {
  assert.equal(pkg.types, pkg.exports['.'].types);
});

for (const [entry, target] of Object.entries(pkg.exports)) {
  test(`${entry}: declarations exist and cover every runtime export`, async () => {
    assert.equal(typeof target, 'object', `${entry} must use a { types, default } conditional export`);
    const keys = Object.keys(target);
    assert.equal(keys[0], 'types', `${entry}: "types" must come first so TypeScript picks it up`);
    const dts = path.join(root, target.types);
    assert.ok(fs.existsSync(dts), `${entry}: missing ${target.types}`);
    const runtime = Object.keys(await import(pathToFileURL(path.join(root, target.default))));
    const declared = declaredValues(dts);
    const missing = runtime.filter((n) => !declared.has(n));
    assert.deepEqual(missing, [], `${entry}: runtime exports with no declaration in ${target.types}`);
    const extra = [...declared].filter((n) => !runtime.includes(n));
    assert.deepEqual(extra, [], `${entry}: declared in ${target.types} but not exported at runtime`);
  });
}
