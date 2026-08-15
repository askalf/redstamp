// Guard: the framework coverage matrix (arena/frameworks.mjs) must stay in sync
// with the corpus and with the published frameworks — a new detection family
// can't ship unmapped, a mapping can't point at a framework item that doesn't
// exist, and the committed FRAMEWORKS.md can't drift from what the generator
// produces. These are the failure modes that turn a credibility asset into a
// liability (an out-of-date or over-claiming coverage table).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  FAMILY, OWASP_LLM, OWASP_AGENTIC, ATLAS,
  OWASP_LLM_VERDICT, OWASP_AGENTIC_VERDICT, build,
} from '../arena/frameworks.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const arena = path.join(here, '..', 'arena');
const corpus = JSON.parse(fs.readFileSync(path.join(arena, 'corpus.json'), 'utf8'));

const llmIds = new Set(OWASP_LLM.map(([id]) => id));
const agenticIds = new Set(OWASP_AGENTIC.map(([id]) => id));
const atlasIds = new Set(Object.keys(ATLAS));

test('every non-benign corpus family is mapped in FAMILY', () => {
  const nonBenign = corpus.families.filter((f) => f !== 'benign');
  const unmapped = nonBenign.filter((f) => !FAMILY[f]);
  assert.deepEqual(unmapped, [], `unmapped families: ${unmapped.join(', ')}`);
});

test('every FAMILY entry only references framework items that exist', () => {
  for (const [name, m] of Object.entries(FAMILY)) {
    for (const id of m.llm) assert.ok(llmIds.has(id), `${name}: unknown OWASP-LLM id ${id}`);
    for (const id of m.agentic) assert.ok(agenticIds.has(id), `${name}: unknown OWASP-Agentic id ${id}`);
    for (const id of m.atlas) assert.ok(atlasIds.has(id), `${name}: unknown ATLAS id ${id}`);
    assert.ok(['core', 'strong', 'partial'].includes(m.scope), `${name}: bad scope ${m.scope}`);
    assert.ok(m.llm.length + m.agentic.length > 0, `${name}: mapped to no framework item`);
  }
});

test('every framework item has a scope verdict', () => {
  const ok = new Set(['covered', 'partial', 'out']);
  for (const [id] of OWASP_LLM) {
    assert.ok(OWASP_LLM_VERDICT[id], `OWASP-LLM ${id} has no verdict`);
    assert.ok(ok.has(OWASP_LLM_VERDICT[id][0]), `OWASP-LLM ${id} bad verdict`);
  }
  for (const [id] of OWASP_AGENTIC) {
    assert.ok(OWASP_AGENTIC_VERDICT[id], `OWASP-Agentic ${id} has no verdict`);
    assert.ok(ok.has(OWASP_AGENTIC_VERDICT[id][0]), `OWASP-Agentic ${id} bad verdict`);
  }
});

test('a covered/partial framework item is backed by at least one mapped family (except audit-only T8)', () => {
  const auditOnly = new Set(['T8']); // repudiation is an audit control, not a family
  for (const [id] of OWASP_LLM) {
    const [verdict] = OWASP_LLM_VERDICT[id];
    if (verdict === 'covered') {
      const has = Object.values(FAMILY).some((m) => m.llm.includes(id));
      assert.ok(has, `OWASP-LLM ${id} is 'covered' but no family maps to it`);
    }
  }
  for (const [id] of OWASP_AGENTIC) {
    const [verdict] = OWASP_AGENTIC_VERDICT[id];
    if (verdict === 'covered' && !auditOnly.has(id)) {
      const has = Object.values(FAMILY).some((m) => m.agentic.includes(id));
      assert.ok(has, `OWASP-Agentic ${id} is 'covered' but no family maps to it`);
    }
  }
});

test('committed FRAMEWORKS.md is not stale (run `npm run arena:frameworks` if this fails)', () => {
  const { md } = build();
  const norm = (s) => s.replace(/\r\n/g, '\n'); // CRLF-agnostic: a Windows checkout must not fail this
  const committed = fs.readFileSync(path.join(arena, 'FRAMEWORKS.md'), 'utf8');
  assert.equal(norm(committed), norm(md), 'FRAMEWORKS.md drifted from the generator');
});
