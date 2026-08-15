// Framework coverage matrix — map redstamp's detection families onto the
// security frameworks buyers, auditors, and reviewers actually speak, then back
// every coverage claim with a MEASURED number from the arena corpus.
//
// Why this exists: "we catch attacks" is anecdote until it's expressed in a
// shared vocabulary and tied to evidence. This file maps each of redstamp's
// non-benign detection families to:
//   - OWASP Top 10 for LLM Applications (2025)
//   - OWASP Agentic AI — Threats & Mitigations (T1–T15)
//   - MITRE ATT&CK (Enterprise) — the TTP each family realises
//   - MITRE ATLAS — the LLM-specific adversarial-ML techniques
//   - NIST AI RMF — the function each detection serves
// then loads arena/corpus.json, runs redstamp's own `decide()` over it, and
// prints, per framework item: is it in scope, which families cover it, and the
// measured block+gate recall on those families' malicious/risky samples.
//
// HONESTY IS THE POINT. redstamp is a tool-call action firewall + secret-exfil
// + injection scanner + tamper-evident audit. It is NOT a RAG/embedding guard,
// a training-data-poisoning defense, a misinformation classifier, or a rate
// limiter — and the matrix says so, out loud, per row. A framework row redstamp
// does not address is marked `out` with a one-line reason, never quietly
// dropped. Over-claiming coverage on a security tool is the failure mode this
// file is built to prevent.
//
//   node arena/frameworks.mjs           # → arena/FRAMEWORKS.md + arena/frameworks.json
//   node arena/frameworks.mjs --check   # exit 1 if FRAMEWORKS.md is stale (CI guard)
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { decide } from '../src/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));

// Same posture the arena's warden adapter uses, so recall here == arena recall.
const policy = { egressAllow: ['api.example.com'], writeRoots: ['src/', 'docs/'] };

// ── Canonical framework item lists (stable IDs only; see honesty note above) ──

export const OWASP_LLM = [
  ['LLM01', 'Prompt Injection'],
  ['LLM02', 'Sensitive Information Disclosure'],
  ['LLM03', 'Supply Chain'],
  ['LLM04', 'Data and Model Poisoning'],
  ['LLM05', 'Improper Output Handling'],
  ['LLM06', 'Excessive Agency'],
  ['LLM07', 'System Prompt Leakage'],
  ['LLM08', 'Vector and Embedding Weaknesses'],
  ['LLM09', 'Misinformation'],
  ['LLM10', 'Unbounded Consumption'],
];

export const OWASP_AGENTIC = [
  ['T1', 'Memory Poisoning'],
  ['T2', 'Tool Misuse'],
  ['T3', 'Privilege Compromise'],
  ['T4', 'Resource Overload'],
  ['T5', 'Cascading Hallucination Attacks'],
  ['T6', 'Intent Breaking & Goal Manipulation'],
  ['T7', 'Misaligned & Deceptive Behaviors'],
  ['T8', 'Repudiation & Untraceability'],
  ['T9', 'Identity Spoofing & Impersonation'],
  ['T10', 'Overwhelming Human-in-the-Loop'],
  ['T11', 'Unexpected RCE and Code Attacks'],
  ['T12', 'Agent Communication Poisoning'],
  ['T13', 'Rogue Agents in Multi-Agent Systems'],
  ['T14', 'Human Attacks on Multi-Agent Systems'],
  ['T15', 'Human Manipulation'],
];

// MITRE ATLAS — only IDs asserted with confidence are shown; families without a
// stable ATLAS mapping are left blank rather than guessed.
export const ATLAS = {
  'AML.T0051': 'LLM Prompt Injection',
  'AML.T0053': 'LLM Plugin Compromise',
  'AML.T0054': 'LLM Jailbreak',
  'AML.T0057': 'LLM Data Leakage',
};

// ── Per-family framework mapping. `scope`: core | strong | partial.
// Every non-benign corpus family MUST appear here (a test enforces it). ──
export const FAMILY = {
  'destructive-fs': {
    desc: 'Recursive filesystem destruction (rm -rf /, wipe roots)',
    llm: ['LLM06'], agentic: ['T2', 'T4'], attack: ['T1485', 'T1561'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'rm-root': {
    desc: 'Root/system-root deletion variants',
    llm: ['LLM06'], agentic: ['T2', 'T4'], attack: ['T1485'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'destructive-win': {
    desc: 'Windows destructive delete / registry nuke',
    llm: ['LLM06'], agentic: ['T2', 'T4'], attack: ['T1485', 'T1070'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'device-wipe': {
    desc: 'Raw block-device / disk-structure wipe (dd, wipefs, blkdiscard)',
    llm: ['LLM06'], agentic: ['T4'], attack: ['T1561'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'rce-download': {
    desc: 'Ingress-and-execute download cradles (curl|bash, certutil, LOLBins)',
    llm: ['LLM05', 'LLM06'], agentic: ['T11'], attack: ['T1105', 'T1059'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'rce-pipe': {
    desc: 'Pipe-to-interpreter remote code execution',
    llm: ['LLM05', 'LLM06'], agentic: ['T11'], attack: ['T1059'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'reverse-shell': {
    desc: 'Reverse/bind shells across languages and tools',
    llm: ['LLM06'], agentic: ['T11'], attack: ['T1059', 'T1219'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'git-rce': {
    desc: 'RCE via git config / ext:: / hooks (supply-chain shaped)',
    llm: ['LLM03', 'LLM05'], agentic: ['T11'], attack: ['T1059', 'T1195'], atlas: ['AML.T0053'],
    nist: ['MEASURE', 'MANAGE'], scope: 'strong',
  },
  'obfuscation': {
    desc: 'Var-indirection / hex / IFS / brace evasion of the classifier',
    llm: ['LLM01', 'LLM06'], agentic: ['T11'], attack: ['T1027', 'T1140'], atlas: ['AML.T0054'],
    nist: ['MEASURE'], scope: 'strong',
  },
  'parser-diff': {
    desc: 'Shell-parser-differential evasion (quoting/skeleton tricks)',
    llm: ['LLM05'], agentic: ['T11'], attack: ['T1027', 'T1036'], atlas: ['AML.T0054'],
    nist: ['MEASURE'], scope: 'strong',
  },
  'exfil': {
    desc: 'Credential/secret egress to an external host',
    llm: ['LLM02'], agentic: ['T2'], attack: ['T1048', 'T1567'], atlas: ['AML.T0057'],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'exfil-bulk': {
    desc: 'Bulk/staged data exfiltration (archive-and-ship)',
    llm: ['LLM02'], agentic: ['T2'], attack: ['T1048', 'T1074'], atlas: ['AML.T0057'],
    nist: ['MEASURE', 'MANAGE'], scope: 'strong',
  },
  'secret-theft': {
    desc: 'Reading credentials / keys / cred stores',
    llm: ['LLM02'], agentic: ['T2', 'T3'], attack: ['T1552', 'T1003'], atlas: ['AML.T0057'],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'ssrf-metadata': {
    desc: 'Cloud instance-metadata SSRF (IMDS credential theft)',
    llm: ['LLM02', 'LLM06'], agentic: ['T2', 'T3'], attack: ['T1552'], atlas: ['AML.T0057'],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'persistence-unix': {
    desc: 'Unix persistence (cron, rc/profile, systemd)',
    llm: ['LLM06'], agentic: ['T2'], attack: ['T1053', 'T1546'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'persistence-win': {
    desc: 'Windows persistence (Run keys, scheduled tasks, services)',
    llm: ['LLM06'], agentic: ['T2'], attack: ['T1547', 'T1053'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'security-disable': {
    desc: 'Disabling defenses (firewall, AV, SELinux, audit)',
    llm: ['LLM06'], agentic: ['T3'], attack: ['T1562'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'windows-ttp': {
    desc: 'Windows LOLBin / system-binary-proxy abuse',
    llm: ['LLM06'], agentic: ['T11'], attack: ['T1218', 'T1003'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'strong',
  },
  'container-escape': {
    desc: 'Escape to host from a container',
    llm: ['LLM06'], agentic: ['T3'], attack: ['T1611'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'core',
  },
  'privesc': {
    desc: 'Local privilege escalation',
    llm: ['LLM06'], agentic: ['T3'], attack: ['T1548', 'T1068'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'strong',
  },
  'kernel-module': {
    desc: 'Kernel module / extension loading',
    llm: ['LLM06'], agentic: ['T3'], attack: ['T1547'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'strong',
  },
  'injection-skill': {
    desc: 'Prompt injection in untrusted skill/tool text & tool results',
    llm: ['LLM01', 'LLM05'], agentic: ['T6', 'T12'], attack: [], atlas: ['AML.T0051', 'AML.T0053'],
    nist: ['MAP', 'MEASURE'], scope: 'core',
  },
  'risky-infra': {
    desc: 'Dual-use infra actions escalated for human review',
    llm: ['LLM06', 'LLM10'], agentic: ['T2', 'T4'], attack: ['T1496'], atlas: [],
    nist: ['MEASURE', 'MANAGE'], scope: 'partial',
  },
  'type-confusion': {
    desc: 'Malformed/typed action inputs the classifier must survive (fail-safe)',
    llm: ['LLM05'], agentic: ['T11'], attack: ['T1027'], atlas: [],
    nist: ['MEASURE'], scope: 'partial',
  },
};

// The audit surface is a control that isn't a detection family. Called out so
// the OWASP-Agentic T8 (repudiation) claim is honest about where it comes from.
const CONTROL_NOTES = {
  T8: 'Covered by the tamper-evident hash-chained audit log (verifyAuditFile / checkpoint), not the action classifier — every allowed/blocked verdict is recorded in an append-only, verifiable chain.',
};

// Per-framework scope verdicts: covered / partial / out + one-line reason.
export const OWASP_LLM_VERDICT = {
  LLM01: ['covered', 'Screens prompt-injection text in untrusted skill/tool descriptions and tool results; neutralises injected instructions before they reach the agent.'],
  LLM02: ['covered', 'Blocks credential/secret egress and cloud-metadata SSRF; flags secret reads.'],
  LLM03: ['partial', 'Catches supply-chain-shaped RCE (git ext::/hooks) and poisoned-skill text; full dependency/provenance pinning is redstamp\'s sibling truecopy, not this classifier.'],
  LLM04: ['out', 'Training-data / model poisoning is out of scope for a runtime tool-call firewall (runtime instruction-poisoning is covered under LLM01).'],
  LLM05: ['covered', 'The LLM\'s output IS the tool call — redstamp validates and blocks the downstream action, and neutralises injected tool-result output.'],
  LLM06: ['covered', 'Core thesis: constrains agent agency by blocking destructive, persistence, privilege, and defense-evasion actions and escalating dual-use ones.'],
  LLM07: ['partial', 'Does not protect system-prompt text itself, but blocks egress of the secrets a leaked prompt would try to carry (via LLM02 families).'],
  LLM08: ['out', 'RAG / vector-store / embedding weaknesses are a different layer; redstamp does not inspect retrieval.'],
  LLM09: ['out', 'Misinformation / hallucination content is not a tool-call action; out of scope.'],
  LLM10: ['partial', 'Escalates some resource-heavy infra actions, but redstamp is not a rate/cost limiter — unbounded consumption is only partially addressed.'],
};

export const OWASP_AGENTIC_VERDICT = {
  T1: ['out', 'Agent memory stores are not inspected; runtime instruction poisoning is covered under T6/LLM01.'],
  T2: ['covered', 'Tool misuse is the primary axis — every action is classified before execution.'],
  T3: ['covered', 'Blocks privilege escalation, container escape, kernel-module load, and defense disabling.'],
  T4: ['partial', 'Blocks destructive availability attacks; not a resource/rate limiter for compute overload.'],
  T5: ['out', 'Cascading hallucination is a reasoning-chain failure, not a tool-call action.'],
  T6: ['partial', 'Indirect injection that redirects intent is screened at the injected-text and resulting-action level.'],
  T7: ['out', 'Deceptive-behavior detection needs trajectory/goal modelling redstamp does not do.'],
  T8: ['covered', CONTROL_NOTES.T8],
  T9: ['out', 'Agent identity/impersonation is an auth-layer concern, out of scope.'],
  T10: ['partial', 'Deterministic verdicts and an approve tier reduce human-review flooding, but the escalation-volume design is the operator\'s.'],
  T11: ['covered', 'RCE via download cradles, pipe-to-interpreter, reverse shells, git-RCE, and obfuscated exec is core coverage.'],
  T12: ['partial', 'The MCP proxy scans inter-tool results/skill text for poisoning (injection-skill family).'],
  T13: ['out', 'Multi-agent rogue-agent detection is out of scope for a single action firewall.'],
  T14: ['out', 'Multi-agent human-attack surface is out of scope.'],
  T15: ['out', 'Human manipulation is a social/UX concern, not a tool-call action.'],
};

// ── Pure helpers ──
const pf = (x) => (x == null ? '—' : (100 * x).toFixed(0) + '%');
const badge = { covered: '✅ covered', partial: '🟡 partial', out: '⬜ out of scope' };

function loadPerFamily() {
  const corpus = JSON.parse(fs.readFileSync(path.join(here, 'corpus.json'), 'utf8'));
  const perFamily = new Map();
  for (const s of corpus.samples) {
    const v = decide(s.action, policy, s.skill || '');
    const prevented = v.decision === 'block' || v.decision === 'approve';
    const rec = perFamily.get(s.family) || {
      block: { tot: 0, prevented: 0 }, approve: { tot: 0, prevented: 0 }, allow: { tot: 0, fp: 0 },
    };
    if (s.expect === 'block') { rec.block.tot++; if (prevented) rec.block.prevented++; }
    else if (s.expect === 'approve') { rec.approve.tot++; if (prevented) rec.approve.prevented++; }
    else if (s.expect === 'allow') { rec.allow.tot++; if (v.decision === 'block') rec.allow.fp++; }
    perFamily.set(s.family, rec);
  }
  return { corpus, perFamily };
}

const measure = (families, perFamily) => {
  let tot = 0, prevented = 0;
  for (const f of families) {
    const r = perFamily.get(f);
    if (!r) continue;
    tot += r.block.tot + r.approve.tot;
    prevented += r.block.prevented + r.approve.prevented;
  }
  return { tot, prevented, pct: tot ? prevented / tot : null };
};

const familiesFor = (kind, id) => Object.entries(FAMILY)
  .filter(([, m]) => (kind === 'llm' ? m.llm : m.agentic).includes(id))
  .map(([name]) => name);

function frameworkSection(title, items, verdictMap, kind, perFamily, opts = {}) {
  const lines = [`## ${title}`, '', opts.blurb || '', '',
    '| # | risk | redstamp | families | measured prevent-recall |',
    '|---|---|---|---|---|'];
  let covered = 0, partial = 0;
  const rows = [];
  for (const [id, name] of items) {
    const [verdict, reason] = verdictMap[id];
    if (verdict === 'covered') covered++;
    else if (verdict === 'partial') partial++;
    const fams = familiesFor(kind, id);
    const m = measure(fams, perFamily);
    const famStr = fams.length ? fams.join(', ') : '—';
    const recStr = fams.length && verdict !== 'out' ? `${pf(m.pct)} (${m.prevented}/${m.tot})` : '—';
    lines.push(`| ${id} | ${name} | ${badge[verdict]} | ${famStr} | ${recStr} |`);
    rows.push({ id, name, verdict, reason, families: fams, measured: m });
  }
  lines.push('');
  lines.push(`**Coverage: ${covered} covered · ${partial} partial · ${items.length - covered - partial} out of scope** — of ${items.length}.`);
  lines.push('');
  lines.push('_Scope reasons (honest, per row):_');
  for (const r of rows) lines.push(`- **${r.id} ${r.name}** — ${badge[r.verdict]}. ${r.reason}`);
  lines.push('');
  return { md: lines.join('\n'), rows, covered, partial };
}

// ── Build the doc + json. Pure: returns strings, writes nothing. ──
export function build() {
  const { corpus, perFamily } = loadPerFamily();
  const nonBenign = corpus.families.filter((f) => f !== 'benign');
  const unmapped = nonBenign.filter((f) => !FAMILY[f]);
  if (unmapped.length) throw new Error(`unmapped families (add to FAMILY in frameworks.mjs): ${unmapped.join(', ')}`);

  const llmSec = frameworkSection(
    'OWASP Top 10 for LLM Applications (2025)', OWASP_LLM, OWASP_LLM_VERDICT, 'llm', perFamily,
    { blurb: 'The reference risk list for LLM apps. redstamp is a tool-call firewall, so it lands squarely on the action-and-output risks (LLM05/LLM06) and the data-egress risks (LLM01/LLM02) — and is explicit about the retrieval/model/misinformation risks it does not address.' },
  );
  const agenticSec = frameworkSection(
    'OWASP Agentic AI — Threats & Mitigations (T1–T15)', OWASP_AGENTIC, OWASP_AGENTIC_VERDICT, 'agentic', perFamily,
    { blurb: 'The agent-specific threat catalogue. redstamp\'s home is Tool Misuse (T2), Privilege Compromise (T3), and Unexpected RCE (T11), plus Repudiation (T8) via its tamper-evident audit — with the multi-agent and social threats out of scope by design.' },
  );

  const matrixLines = ['## Family → framework matrix', '',
    'Every non-benign detection family, with the framework items it realises and its measured recall on this corpus.', '',
    '| family | scope | samples (blk/appr) | recall | OWASP-LLM | OWASP-Agentic | ATT&CK | ATLAS |',
    '|---|---|---|---|---|---|---|---|'];
  const matrixRows = [];
  for (const f of nonBenign.slice().sort()) {
    const m = FAMILY[f];
    const r = perFamily.get(f) || { block: { tot: 0, prevented: 0 }, approve: { tot: 0, prevented: 0 } };
    const tot = r.block.tot + r.approve.tot, prevented = r.block.prevented + r.approve.prevented;
    const rec = tot ? prevented / tot : null;
    matrixLines.push(`| ${f} | ${m.scope} | ${r.block.tot}/${r.approve.tot} | ${pf(rec)} (${prevented}/${tot}) | ${m.llm.join(' ')} | ${m.agentic.join(' ')} | ${m.attack.join(' ') || '—'} | ${m.atlas.join(' ') || '—'} |`);
    matrixRows.push({ family: f, ...m, samples: { block: r.block.tot, approve: r.approve.tot }, recall: rec, prevented, tot });
  }
  matrixLines.push('');

  const atlasFams = Object.entries(FAMILY).filter(([, m]) => m.atlas.length);
  const atlasLines = ['## MITRE ATLAS (LLM-specific adversarial ML)', '',
    'Only ATLAS technique IDs asserted with confidence are shown; families without a stable ATLAS mapping are left blank rather than guessed.', '',
    '| ATLAS technique | name | families |', '|---|---|---|'];
  for (const [id, name] of Object.entries(ATLAS)) {
    const fams = atlasFams.filter(([, m]) => m.atlas.includes(id)).map(([n]) => n);
    atlasLines.push(`| ${id} | ${name} | ${fams.join(', ') || '—'} |`);
  }
  atlasLines.push('');

  const nistLines = ['## NIST AI RMF (function alignment)', '',
    'redstamp is a **MEASURE**-and-**MANAGE** control: it measures the risk of each agent action against a policy and manages the response (allow / escalate / block), with the audit log serving **GOVERN** accountability and the poisoned-skill scan serving **MAP** context.', ''];

  const tally = [...perFamily.values()].reduce((a, r) => ({
    malTot: a.malTot + r.block.tot, malBlocked: a.malBlocked + r.block.prevented,
    riskTot: a.riskTot + r.approve.tot, riskEsc: a.riskEsc + r.approve.prevented,
    benTot: a.benTot + r.allow.tot, benFp: a.benFp + r.allow.fp,
  }), { malTot: 0, malBlocked: 0, riskTot: 0, riskEsc: 0, benTot: 0, benFp: 0 });
  const benPrec = tally.benTot ? (tally.benTot - tally.benFp) / tally.benTot : null;

  const md = [
    '# Framework coverage',
    '',
    `> redstamp\'s ${nonBenign.length} detection families mapped onto the frameworks security teams already use — **OWASP Top 10 for LLM Apps (2025)**, **OWASP Agentic AI Threats**, **MITRE ATT&CK**, **MITRE ATLAS**, and **NIST AI RMF** — with every coverage claim backed by a measured recall number from the arena corpus (\`corpus.json\`, ${corpus.total} samples).`,
    '',
    `Generated by \`node arena/frameworks.mjs\` — never hand-edited. Recall figures use the same \`decide()\` and posture as the arena, so they match [RESULTS.md](RESULTS.md).`,
    '',
    '## Headline',
    '',
    `- **OWASP LLM Top 10 (2025):** ${llmSec.covered} covered, ${llmSec.partial} partial, ${10 - llmSec.covered - llmSec.partial} out of scope — the out-of-scope rows (model poisoning, embeddings, misinformation) are a *different layer*, not a gap.`,
    `- **OWASP Agentic (T1–T15):** ${agenticSec.covered} covered, ${agenticSec.partial} partial — spanning Tool Misuse, Privilege Compromise, RCE, and Repudiation.`,
    `- **Measured:** **${tally.malBlocked}/${tally.malTot}** malicious samples hard-blocked (**${pf(tally.malBlocked / tally.malTot)}** recall) and **${tally.riskEsc}/${tally.riskTot}** risky samples escalated for review, at **${pf(benPrec)}** precision (${tally.benFp}/${tally.benTot} benign false-positives). The one risky under-gate is the documented \`risky-infra\` curl-download-to-disk case — a fetch, not an egress, allowed by design.`,
    '',
    'Coverage without a measured number is a claim; every row below carries both.',
    '',
    llmSec.md,
    agenticSec.md,
    matrixLines.join('\n'),
    atlasLines.join('\n'),
    nistLines.join('\n'),
    '## Honest scope',
    '',
    'This matrix is a **map, not a trophy**. redstamp is one layer — the action firewall between an agent and its tools. Rows marked *out of scope* (training-data poisoning, embeddings, misinformation, multi-agent social threats) are addressed by other layers (retrieval guards, provenance pinning, alignment training), not by this classifier, and saying so is the point. The families it does cover are backed by an open, reproducible corpus and the same `decide()` the product ships.',
    '',
    '_Provenance: framework item lists are the published OWASP / MITRE / NIST catalogues; family→item mappings and scope verdicts are maintained in `arena/frameworks.mjs`; recall numbers are regenerated from `arena/corpus.json`. MIT, same as redstamp._',
    '',
  ].join('\n');

  const json = {
    generatedFrom: 'arena/corpus.json',
    corpusTotal: corpus.total,
    headline: {
      owaspLlm: { covered: llmSec.covered, partial: llmSec.partial, total: 10 },
      owaspAgentic: { covered: agenticSec.covered, partial: agenticSec.partial, total: 15 },
      measured: {
        malBlocked: tally.malBlocked, malTotal: tally.malTot, recall: tally.malBlocked / tally.malTot,
        riskEscalated: tally.riskEsc, riskTotal: tally.riskTot,
        precision: benPrec, benignFp: tally.benFp, benignTotal: tally.benTot,
      },
    },
    owaspLlm: llmSec.rows,
    owaspAgentic: agenticSec.rows,
    matrix: matrixRows,
    atlas: ATLAS,
  };

  return { md, json, summary: { llm: llmSec, agentic: agenticSec, tally, benPrec }, unmapped };
}

// ── CLI ──
const isMain = import.meta.url === pathToFileURL(process.argv[1] || '').href;
if (isMain) {
  let out;
  try { out = build(); }
  catch (e) { console.error(`ERROR: ${e.message}`); process.exit(1); }
  const mdPath = path.join(here, 'FRAMEWORKS.md');
  const jsonPath = path.join(here, 'frameworks.json');
  const jsonStr = JSON.stringify(out.json, null, 2) + '\n';
  if (process.argv.includes('--check')) {
    const curMd = fs.existsSync(mdPath) ? fs.readFileSync(mdPath, 'utf8') : '';
    const norm = (s) => s.replace(/\r\n/g, '\n'); // CRLF-agnostic
    if (norm(curMd) !== norm(out.md)) { console.error('FRAMEWORKS.md is stale — run `npm run arena:frameworks`'); process.exit(1); }
    console.log('FRAMEWORKS.md is up to date'); process.exit(0);
  }
  fs.writeFileSync(mdPath, out.md);
  fs.writeFileSync(jsonPath, jsonStr);
  const { llm, agentic, tally, benPrec } = out.summary;
  console.log('wrote arena/FRAMEWORKS.md + arena/frameworks.json');
  console.log(`OWASP LLM: ${llm.covered} covered / ${llm.partial} partial of 10`);
  console.log(`OWASP Agentic: ${agentic.covered} covered / ${agentic.partial} partial of 15`);
  console.log(`measured: ${tally.malBlocked}/${tally.malTot} malicious blocked, ${tally.riskEsc}/${tally.riskTot} risky escalated, precision ${pf(benPrec)}`);
}
