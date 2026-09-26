// Fuzz the egress allowlist path: the shell destination parser and the host
// normaliser run only when a policy sets egressAllow, which classify.fuzz.js
// never does. Invariants, on arbitrary bytes as a shell command:
//   - it never throws and always returns a well-formed verdict;
//   - an allowed verdict never coexists with a parsed destination outside the
//     allowlist (the parser and the gate must agree);
//   - the parser's outputs are finite and bounded.
import { check } from '../src/index.mjs';
import { shellEgressHosts, shellEgressUnresolved } from '../src/classify.mjs';
import { isExternal } from '../src/scan.mjs';

const TIERS = new Set(['green', 'yellow', 'red', 'black']);
const DECISIONS = new Set(['allow', 'approve', 'block']);
const POLICY = { egressAllow: ['api.example.com', 'github.com'] };

export function fuzz(data) {
  const s = data.toString('utf8');
  const hosts = shellEgressHosts(s);
  const unresolved = shellEgressUnresolved(s);
  if (!Array.isArray(hosts) || hosts.length > 256 || !Array.isArray(unresolved) || unresolved.length > 256) {
    throw new Error(`unbounded parser output for ${JSON.stringify(s)}`);
  }
  const v = check({ tool: 'shell', input: { command: s } }, POLICY);
  if (!v || !TIERS.has(v.tier) || !DECISIONS.has(v.decision) || !Array.isArray(v.why)) {
    throw new Error(`malformed verdict for ${JSON.stringify(s)}: ${JSON.stringify(v)}`);
  }
  if (v.decision === 'allow') {
    const outside = hosts.filter((h) => isExternal(h, POLICY.egressAllow));
    if (outside.length || unresolved.length) {
      throw new Error(`allowed despite egress ${JSON.stringify(outside)} / ${JSON.stringify(unresolved)}: ${JSON.stringify(s)}`);
    }
  }
}
