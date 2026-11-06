#!/bin/sh
# redstamp - own your agent security - https://github.com/askalf/redstamp
#
# Installs the redstamp CLI globally from the signed GitHub release tarball,
# after verifying its Sigstore provenance. Same steps, by hand:
#   gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'
#   gh attestation verify redstamp.tgz --repo askalf/redstamp --bundle redstamp.tgz.sigstore.json
#   npm i -g ./redstamp.tgz
set -eu

REPO="askalf/redstamp"

if ! command -v npm >/dev/null 2>&1; then
  echo "redstamp needs Node.js >= 20 (npm not found) - https://nodejs.org" >&2
  exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "redstamp needs the GitHub CLI to verify provenance (gh not found) - https://cli.github.com" >&2
  exit 1
fi

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "downloading redstamp.tgz from the latest $REPO release"
if ! gh release download --repo "$REPO" --pattern redstamp.tgz --pattern redstamp.tgz.sigstore.json --dir "$TMP"; then
  echo "redstamp: downloading the release assets failed" >&2
  exit 1
fi

# Nothing is installed unless the tarball was built and signed by this repo.
if ! gh attestation verify "$TMP/redstamp.tgz" --repo "$REPO" --bundle "$TMP/redstamp.tgz.sigstore.json"; then
  echo "redstamp: provenance verification failed - not installing" >&2
  exit 1
fi

if ! npm install -g "$TMP/redstamp.tgz"; then
  echo "redstamp: npm install failed" >&2
  exit 1
fi
echo
npm ls -g --depth=0 @askalf/redstamp || true
echo "done - try: redstamp init"
