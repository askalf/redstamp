# @askalf/redstamp

> ### ⚠️ This npm package is a pointer. redstamp is not distributed here.
>
> The real thing lives at **[github.com/askalf/redstamp](https://github.com/askalf/redstamp)** and is actively released — see the version badge below.

[![release](https://img.shields.io/github/v/release/askalf/redstamp?logo=github)](https://github.com/askalf/redstamp/releases/latest)
[![ci](https://github.com/askalf/redstamp/actions/workflows/ci.yml/badge.svg)](https://github.com/askalf/redstamp/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/askalf/redstamp/badge)](https://scorecard.dev/viewer/?uri=github.com/askalf/redstamp)
[![signed release](https://img.shields.io/badge/release-sigstore_signed-brightgreen?logo=github)](https://github.com/askalf/redstamp/releases/latest)
[![dependencies: 0](https://img.shields.io/badge/dependencies-0-brightgreen)](https://github.com/askalf/redstamp/blob/master/package.json)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue)](https://github.com/askalf/redstamp/blob/master/LICENSE)

**redstamp is a deterministic firewall for AI agent tool calls** — it sits between an agent and its tools and, on every action, classifies risk, enforces policy, and blocks secret-exfiltration and prompt-injection before the call runs. Same tool call, same verdict, every time, offline, with no model in the decision path. It ships as a Claude Code hook, a background daemon, an MCP middleware proxy, and a library. Zero dependencies.

## Install

Releases are **Sigstore-signed tarballs** published on GitHub:

```sh
# fetch the latest signed release + its provenance
gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'

# verify provenance BEFORE installing — exits non-zero if it isn't ours
gh attestation verify redstamp.tgz --repo askalf/redstamp --bundle redstamp.tgz.sigstore.json

npm i -g ./redstamp.tgz
```

Then follow the [setup guide](https://github.com/askalf/redstamp#readme) to wire it in as a Claude Code hook, a daemon, or an MCP proxy.

## Why isn't it on npm?

redstamp detects prompt-injection, secret-exfiltration, and destructive-command patterns — so its source necessarily *contains* a large corpus of those patterns, held as detection data. That is the same shape as an antivirus definition file, and npm's automated content scan reads it as malware and rejects the upload. An allowlist review was declined.

We won't obfuscate, encode, or split those signatures to get past a scanner. That is detection evasion, and it would destroy the plain-source auditability that ought to be the reason you trust a security tool at all.

So redstamp is distributed as signed release tarballs with provenance you can verify yourself — a stronger integrity guarantee than an unsigned registry install. This package exists only so that this page tells you where to go.

---

Part of **[Own Your Stack](https://github.com/askalf)** — own your AI infrastructure instead of renting it by the token.
