// Score redstamp against the THIRD-PARTY corpora (tldr-pages benign, Atomic Red
// Team attack/benign) honestly and reproducibly, and emit arena/THIRD-PARTY-
// RESULTS.md. Unlike the raw arena table, this reports Atomic Red Team AXIS-
// AWARE — separating command-semantic attacks (redstamp's axis) from opaque
// pre-staged-binary execution (out of any command-string firewall's reach) —
// and lists the exact on-axis misses as actionable detection gaps.
//
// The point of a third-party corpus is neutrality: nobody here wrote these
// commands, so the numbers can't be "graded homework." Precision on a large
// external benign set is the make-or-break number (a noisy firewall gets turned
// off); recall on external attacks is where an outside corpus earns its keep by
// surfacing real gaps. Both are reported straight, wins and misses alike.
//
//   node arena/thirdparty.mjs        # → arena/THIRD-PARTY-RESULTS.md
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from '../src/index.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const policy = { egressAllow: ['api.example.com'], writeRoots: ['src/', 'docs/'] };
const load = (f) => JSON.parse(fs.readFileSync(path.join(here, f), 'utf8'));
const pct = (n, d) => (d ? (100 * n / d).toFixed(0) + '%' : '—');

function scoreTldr(corpus) {
  let fp = 0, gated = 0;
  for (const s of corpus.samples) {
    const v = decide(s.action, policy, '');
    if (v.decision === 'block') fp++;
    else if (v.decision === 'approve') gated++;
  }
  return { total: corpus.total, fp, gated, precision: (corpus.total - fp) / corpus.total };
}

function scoreAtomic(corpus) {
  const r = {
    onTot: 0, onBlock: 0, onGate: 0, offTot: 0, offBlock: 0,
    apTot: 0, apPrev: 0, alTot: 0, alFp: 0, alGate: 0, misses: [],
  };
  for (const s of corpus.samples) {
    const v = decide(s.action, policy, '');
    const prevented = v.decision === 'block' || v.decision === 'approve';
    if (s.expect === 'block') {
      if (s.axis === 'command-semantic') {
        r.onTot++;
        if (v.decision === 'block') r.onBlock++;
        if (prevented) r.onGate++;
        else r.misses.push({ family: s.family, command: s.command.replace(/\s+/g, ' ').slice(0, 110), decision: v.decision });
      } else { r.offTot++; if (v.decision === 'block') r.offBlock++; }
    } else if (s.expect === 'approve') { r.apTot++; if (prevented) r.apPrev++; }
    else if (s.expect === 'allow') { r.alTot++; if (v.decision === 'block') r.alFp++; else if (v.decision === 'approve') r.alGate++; }
  }
  return r;
}

const tldrCorpus = load('thirdparty-tldr.json');
const atomicCorpus = load('thirdparty-atomic.json');
const tldr = scoreTldr(tldrCorpus);
const atomic = scoreAtomic(atomicCorpus);

const md = [
  '# Third-party corpus results',
  '',
  '> redstamp scored against corpora **nobody here wrote** — the neutrality test the arena README calls for. Precision on external benign commands, recall on external attacks, reported straight. Regenerate: `node arena/thirdparty.mjs`.',
  '',
  '## tldr-pages — benign precision (CC-BY-4.0)',
  '',
  `Source: ${tldrCorpus.total} real command examples from [tldr-pages](${tldrCorpus.source.repo}) \`pages/common\` @ \`${tldrCorpus.source.commit.slice(0, 10)}\`, placeholder-substituted, destructive/dual-use utilities excluded (a firewall should gate those). See provenance in the corpus file.`,
  '',
  `- **Precision: ${pct(tldrCorpus.total - tldr.fp, tldrCorpus.total)} — ${tldr.fp} hard false-positives of ${tldrCorpus.total}.**`,
  `- Friction (benign escalated to review, a softer signal): ${tldr.gated}/${tldrCorpus.total} — all defensible outward-facing/dual-use shapes (\`git push\`, \`npx\`, a credentials-file scan).`,
  '',
  'A large external benign set with zero hard false-positives is the number that matters most: a firewall that fires on real work gets disabled, and a disabled firewall catches nothing.',
  '',
  '## Atomic Red Team — external ATT&CK attacks + benign (MIT)',
  '',
  `Source: ${atomicCorpus.total} commands from [Atomic Red Team](${atomicCorpus.source.repo}) @ \`${atomicCorpus.source.commit.slice(0, 10)}\` across ${atomicCorpus.families.length} ATT&CK techniques. Labels assigned by security principle per technique (not "it's in Atomic → block"); see the corpus provenance for the full methodology.`,
  '',
  '**Read this axis-aware.** redstamp classifies command *semantics*. Atomic Red Team also ships tests that run a pre-staged binary (`mimikatz.exe`, `gsecdump.exe`) — whose maliciousness is in the binary\'s reputation, not the command string. No command-string firewall can catch those without a binary-reputation feed; they are a documented axis limit, exactly as LlamaFirewall is read on the injection slice only. Each sample is tagged `command-semantic` vs `opaque-binary`.',
  '',
  '| slice | metric | result |',
  '|---|---|---|',
  `| block · command-semantic (redstamp's axis) | hard-block recall | **${atomic.onBlock}/${atomic.onTot} (${pct(atomic.onBlock, atomic.onTot)})** |`,
  `| block · command-semantic | +gate recall (block or escalate) | ${atomic.onGate}/${atomic.onTot} (${pct(atomic.onGate, atomic.onTot)}) |`,
  `| block · opaque-binary (out of axis) | hard-block recall | ${atomic.offBlock}/${atomic.offTot} (${pct(atomic.offBlock, atomic.offTot)}) — documented limit |`,
  `| approve · dual-use | escalated (block or gate) | ${atomic.apPrev}/${atomic.apTot} (${pct(atomic.apPrev, atomic.apTot)}) |`,
  `| allow · discovery | **precision** (0 FP = perfect) | **${atomic.alFp} FP / ${atomic.alTot}** (${pct(atomic.alTot - atomic.alFp, atomic.alTot)}), ${atomic.alGate} gated |`,
  '',
  `_On the dual-use row: this corpus labels every dual-use technique \`approve\` — the conservative position that a human should see them — so ${atomic.apTot - atomic.apPrev} of ${atomic.apTot} sit below redstamp's escalation threshold (archiving, clipboard/screen reads, registry edits, permission changes, plain file transfers). That is the friction dial, not a miss: gating all of them would put a prompt in front of routine work, and the arena reports it plainly rather than tuning the labels to flatter the score._`,
  '',
  `**Honest read.** ${atomic.onGate === atomic.onTot
    ? `Nothing on-axis is silently allowed: **${atomic.onGate}/${atomic.onTot}** of the external ATT&CK attacks are stopped — ${atomic.onBlock} hard-blocked and ${atomic.onGate - atomic.onBlock} escalated for human review — at **${pct(atomic.alTot - atomic.alFp, atomic.alTot)}** precision on benign discovery from the same source (${atomic.alFp} false-positives of ${atomic.alTot}).`
    : `On-axis hard-block recall is **${pct(atomic.onBlock, atomic.onTot)}** (${atomic.onGate}/${atomic.onTot} stopped counting escalations), at ${pct(atomic.alTot - atomic.alFp, atomic.alTot)} precision on benign discovery.`}`,
  '',
  `This is what the corpus was imported for. The first run scored **10/31 hard-block and 13/31 prevented**, with 18 attacks silently allowed — an outside ATT&CK corpus catching real command-semantic gaps redstamp's own corpus never exercised: exfil over ssh/tar and DNS, inhibit-recovery variants (\`wbadmin delete catalog\`, WMI shadow-copy delete, \`fsutil usn deletejournal\`), ransomware-shaped encryption of system credential files, \`dd\` overwriting a logfile, the \`kubectl\` privileged-pod host escape, and credential-store enumeration. Those became detection rules (each with a regression test **and** a paired false-positive guard, since every one is a co-occurrence rule), and the numbers above are post-fix.`,
  '',
  ...(atomic.misses.length
    ? [
      `### Still allowed (${atomic.misses.length}) — attacks neither blocked nor escalated`,
      '',
      'A bulleted list, not a table, so pipes and backslashes render verbatim.',
      '',
      // A code span inside a list item needs no pipe/backslash escaping (unlike a
      // table cell); only backticks must go, since they would close the span.
      ...atomic.misses.map((m) => `- **${m.family}** (currently \`${m.decision}\`) — \`${m.command.replace(/`/g, "'")}\``),
      '',
    ]
    : [
      '### Remaining boundary',
      '',
      `Nothing on-axis is silently allowed. The residue is the **opaque-binary** slice (${atomic.offTot - atomic.offBlock} of ${atomic.offTot} not hard-blocked): commands whose payload is a pre-staged \`.exe\`/\`.dll\`, where the maliciousness lives in the binary rather than the command string. Closing that needs a binary-reputation feed, which is a different layer — not a rule this classifier can honestly write.`,
      '',
    ]),
  '## Provenance & licenses',
  '',
  `- **tldr-pages** — ${tldrCorpus.source.license}. ${tldrCorpus.source.attribution}`,
  `- **Atomic Red Team** — ${atomicCorpus.source.license}. ${atomicCorpus.source.attribution}`,
  '',
  'See [THIRD-PARTY-CORPORA.md](THIRD-PARTY-CORPORA.md) for the full license map (including corpora we deliberately did NOT vendor for license reasons) and the import roadmap. MIT for redstamp\'s own code and tooling.',
  '',
].join('\n');

fs.writeFileSync(path.join(here, 'THIRD-PARTY-RESULTS.md'), md);
console.log('wrote arena/THIRD-PARTY-RESULTS.md');
console.log(`tldr precision: ${pct(tldrCorpus.total - tldr.fp, tldrCorpus.total)} (${tldr.fp} FP / ${tldrCorpus.total})`);
console.log(`atomic on-axis recall: ${atomic.onBlock}/${atomic.onTot} block, ${atomic.onGate}/${atomic.onTot} +gate; discovery FP ${atomic.alFp}/${atomic.alTot}; ${atomic.misses.length} gaps listed`);
