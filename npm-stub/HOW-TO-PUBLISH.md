# Publishing the pointer package

This directory is **not** redstamp. It is the tiny package that occupies
`@askalf/redstamp` on npm so that anyone landing there is told, immediately and
accurately, where the real thing is and why it is not on the registry.

It exists because npm's automated content scan rejects redstamp's real tarball
(its detection-signature corpus reads as malware — see the README) and an
allowlist review was declined. A minimal tarball with no signature corpus
publishes fine; that was proven by the `0.0.2-diag.0` canary.

## Publish

Run from **this directory**, with an npm account that owns the `@askalf` scope:

The account's second factor is a **security key (WebAuthn), not TOTP** — so
there is no code to type and `--otp=` is impossible. A plain `npm publish`
therefore dies with `EOTP`, and no account-level 2FA setting fixes it. Use the
browser ceremony instead, in a **real PowerShell window**:

```powershell
cd "C:\Users\masterm1nd\Desktop\codebase\warden\npm-stub"
npx.cmd npm@latest publish --access public
```

Three details, each of which has cost an attempt before:

- **A real terminal, not an agent shell.** Claude Code / CI shells are
  non-TTY and the ceremony cannot run there.
- **`npx.cmd npm@latest`**, because the box's npm (10.x) lacks the web-auth
  publish flow — npm 12 has it.
- **`.cmd`, never the `.ps1` shim**, which the execution policy blocks.

npm prints an `npmjs.com/auth/cli/…` URL; approve it with the key and the
publish completes.

`files` limits the tarball to `index.mjs` (npm always adds `package.json`,
`README.md`, `LICENSE`). Nothing from the parent repo is included — in
particular no `src/`, so there is no signature corpus to trip the scan.

## Then mark it deprecated

The deprecation notice is what puts a banner on the npm page and warns anyone
who installs it. Do this **after** the publish lands:

```sh
npm deprecate @askalf/redstamp "Not distributed on npm — npm's content scan rejects redstamp's detection-signature corpus. Install the signed release: https://github.com/askalf/redstamp/releases"
```

To reverse it later (for example if npm ever allowlists the real package),
publish the real version and clear the notice with an empty message:

```sh
npm deprecate @askalf/redstamp ""
```

## Do not

- Do not bump this to a version that resembles a real redstamp release. The
  `0.0.x` line is deliberate: it must never look like the current release.
- Do not add code here beyond the throwing pointer in `index.mjs`.
- Do not vendor any of `src/` into this package to "make npm work".
