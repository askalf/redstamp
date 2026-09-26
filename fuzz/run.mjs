// `node fuzz/run.mjs` (also `npm run fuzz`) runs every Jazzer.js target in ./fuzz. This is the
// fuzzer CI runs (.github/workflows/fuzz.yml) and the local repro loop. Environment:
//   FUZZ_SECONDS       per-target budget in seconds (default 30)
//   FUZZ_CORPUS_DIR    root of per-target corpus dirs, created on demand; libFuzzer reads its
//                      seeds from <dir>/<target> and saves every interesting input there, so a
//                      corpus that persists between runs keeps getting deeper. Unset: no corpus.
//   FUZZ_ARTIFACT_DIR  where a crashing input is written, created on demand. Unset: the cwd.
//
// redstamp's runtime is zero-dependency, so Jazzer is NOT a devDependency: it is fetched on demand
// with `npx --package`. Nothing is added to package.json or the tarball.
import { spawnSync } from 'node:child_process';
import { mkdirSync, readdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = path.dirname(fileURLToPath(import.meta.url));
const targets = readdirSync(dir).filter((f) => f.endsWith('.fuzz.js')).sort();
const secs = process.env.FUZZ_SECONDS || '30';
const corpusRoot = process.env.FUZZ_CORPUS_DIR || '';
const artifactDir = process.env.FUZZ_ARTIFACT_DIR || '';
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
if (artifactDir) mkdirSync(artifactDir, { recursive: true });

for (const t of targets) {
  const name = t.replace(/\.fuzz\.js$/, '');
  // The targets are synchronous (they never return a promise), so Jazzer runs in --sync mode.
  const args = ['--yes', '--package', '@jazzer.js/core@^4', 'jazzer', `fuzz/${name}.fuzz`, '--sync'];
  if (corpusRoot) {
    const corpus = path.join(corpusRoot, name);
    mkdirSync(corpus, { recursive: true });
    args.push(corpus);
  }
  args.push('--', `-max_total_time=${secs}`, '-print_final_stats=1');
  if (artifactDir) args.push(`-artifact_prefix=${artifactDir}${path.sep}`);
  console.log(`\n=== fuzzing ${name} (${secs}s) ===`);
  const r = spawnSync(npx, args, { stdio: 'inherit', shell: process.platform === 'win32' });
  if (r.status !== 0) {
    console.error(`\n${name}: jazzer exited with ${r.status ?? r.signal}; a reproducing input is in ${artifactDir || 'the working directory'}`);
    process.exit(r.status || 1);
  }
}
