# Installing redstamp

> [!IMPORTANT]
> **Not distributed on npm, and won't be.** `@askalf/redstamp` on the registry is a deprecated pointer stub that throws on import: npm's automated content scan reads redstamp's detection-signature corpus as malware, and an allowlist review was declined. We won't obfuscate or split those signatures to pass a scanner — that's detection evasion, and it would destroy the plain-source auditability that makes a security tool worth trusting.

Install from the Sigstore-signed GitHub release — **verify provenance first**, then install globally so the `redstamp`, `redstamp-hook`, `redstamp-mcp`, and `redstamp-serve` CLIs land on your PATH:

```sh
gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'
gh attestation verify redstamp.tgz --repo askalf/redstamp --bundle redstamp.tgz.sigstore.json   # non-zero unless this exact repo built it
npm i -g ./redstamp.tgz
```

Or the one-line global install (same signed artifact, verification handled for you):

```sh
curl -fsSL https://ownyourstack.sprayberrylabs.com/redstamp.sh | sh
```

```powershell
powershell -c "irm https://ownyourstack.sprayberrylabs.com/redstamp.ps1 | iex"
```

Every tarball is packed in CI and signed with keyless Sigstore. A security tool shouldn't ask for blind trust — that's why the verify step comes *before* the install, not after.

> Git installs (`npm i --allow-git github:askalf/redstamp`) still work but carry **no attestation** — you're trusting the fetch. npm ≥ 12 [blocks git dependencies by default](https://github.blog/changelog/2026-06-09-upcoming-breaking-changes-for-npm-v12/) (supply-chain hardening redstamp applauds); the tarball route needs no flags.

Policy lives in `redstamp.config.json` (`tool(glob)` rules, Claude-Code style — see [`redstamp.config.example.json`](../redstamp.config.example.json)), or run `redstamp init` to generate one from your project.
