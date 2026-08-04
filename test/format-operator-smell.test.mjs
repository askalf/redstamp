// Regression tests for the `-f` arm of the PowerShell string-assembly smell.
//
// The arm added in #123 keyed on `-f\b`, which is the format operator AND the
// ordinary CLI flag. So an assignment holding a command line, followed by any
// `& $var` invocation, smelled of obfuscation and paid for a judge call it did
// not need. The fix keys the arm on a `{N}` PLACEHOLDER instead: PowerShell's
// format operator cannot assemble anything without one (`"a" -f $x` evaluates
// to `"a"`, the operand is discarded), so a placeholder is present in every
// real evasion and absent from every flag usage.
//
// The smell is verdict-neutral — it only routes to the judge, it never blocks —
// so what these tests protect is judge volume on one side and evasion coverage
// on the other. The three false-positive guards FAIL against the pre-fix regex
// (5 pass / 2 fail with `src/scan.mjs` stashed); they constrain the change
// rather than follow it.
//
// Fixtures are BUILT from fragments rather than written literally, per this
// repo's existing convention (see base64-shell-spellings.test.mjs and
// argument-list-separator.test.mjs) — a literal fixture here reads as a live
// payload to the scanners that watch this repo.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { obfuscationHits } from '../src/scan.mjs';

const ASSEMBLY = 'assembles a string then invokes it (PowerShell call operator)';

const smells = (text) => obfuscationHits(text).includes(ASSEMBLY);

const F = '-f';                      // format operator AND ordinary CLI flag
const RM = 'Rem';                    // cmdlet name, split so it is not a literal
const OV = 'ove-Item';

// ── the reported false positives: `-f` as a flag inside an assigned string ──
// Each is an assignment whose value merely CONTAINS `-f`, followed by the
// idiomatic `& $var` call. No placeholder, so no assembly is possible.
test('a -f CLI flag inside an assigned command line raises no smell', () => {
  assert.equal(smells(`$t = "build ${F} Dockerfile -t app ."; & $docker $t`), false);
});

test('an assigned flag string raises no smell', () => {
  assert.equal(smells(`$flags = "${F} Dockerfile"; & $exe $flags`), false);
});

test('a -f flag on a cmdlet in an assignment raises no smell', () => {
  assert.equal(smells(`$p = Get-Content ${F} log.txt; & $p`), false);
});

// ── the evasion the arm exists for must still smell ─────────────────────────
test('the format operator assembling a cmdlet name still smells', () => {
  assert.equal(smells(`$c = "{0}{1}" ${F} "${RM}","${OV}"; & $c`), true);
});

test('the unspaced format-operator spelling still smells', () => {
  // PowerShell parses `"{0}{1}"-f"a","b"` identically; the smell must too.
  assert.equal(smells(`$c = "{0}{1}"${F}"${RM}","${OV}"; & $c`), true);
});

test('a two-digit placeholder index still smells', () => {
  // `{10}` is legal, so the placeholder class is `\d{1,2}`, not a single digit.
  assert.equal(smells(`$c = "{10}{1}" ${F} $a,$b; & $c`), true);
});

// ── the untouched arms, pinned so the -f edit cannot leak into them ─────────
test('-join and "+" concat assembly still smell, a bare call operator does not', () => {
  assert.equal(smells(`$c = "${RM}","${OV}" -join ""; & $c`), true);
  assert.equal(smells(`$c = "${RM}" + "${OV}"; & $c`), true);
  // The call operator alone is idiomatic PowerShell — it was never the smell.
  assert.equal(smells('& $tool --version'), false);
});
