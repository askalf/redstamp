// Continuous guardrail: redstamp must keep ZERO hard false-positives on the
// third-party benign command sets (tldr-pages real commands + Atomic Red Team
// benign discovery). Precision on external benign work is the number that
// decides whether anyone leaves the firewall turned on — a regression that
// starts hard-blocking real benign commands is exactly what this catches, on
// data nobody here wrote. Runs offline against the committed corpus JSONs.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../src/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const arena = path.join(here, '..', 'arena');
const policy = { egressAllow: ['api.example.com'], writeRoots: ['src/', 'docs/'] };

function falsePositives(file) {
  const corpus = JSON.parse(fs.readFileSync(path.join(arena, file), 'utf8'));
  const fps = [];
  for (const s of corpus.samples) {
    if (s.expect !== 'allow') continue;
    const v = decide(s.action, policy, '');
    if (v.decision === 'block') fps.push(`${s.id}: ${s.command.slice(0, 80)}`);
  }
  return { total: corpus.samples.filter((s) => s.expect === 'allow').length, fps };
}

test('tldr-pages: zero hard false-positives on real benign commands', () => {
  const { total, fps } = falsePositives('thirdparty-tldr.json');
  assert.ok(total > 500, `expected a large benign set, got ${total}`);
  assert.deepEqual(fps, [], `false-positives on benign tldr commands:\n${fps.join('\n')}`);
});

test('Atomic Red Team: zero hard false-positives on benign discovery', () => {
  const { total, fps } = falsePositives('thirdparty-atomic.json');
  assert.ok(total > 30, `expected a discovery set, got ${total}`);
  assert.deepEqual(fps, [], `false-positives on benign discovery commands:\n${fps.join('\n')}`);
});
