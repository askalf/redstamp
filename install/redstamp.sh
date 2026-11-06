#!/bin/sh
# redstamp - own your agent security - https://github.com/askalf/redstamp
#
# Installs the redstamp CLI globally from the signed GitHub release tarball. The tarball is
# downloaded, its provenance is checked with gh, and only that checked file reaches npm: a failed
# check installs nothing. The same steps by hand:
#   gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'
#   gh attestation verify redstamp.tgz --repo askalf/redstamp --bundle redstamp.tgz.sigstore.json
#   npm i -g ./redstamp.tgz
set -eu

BASE="https://github.com/askalf/redstamp/releases/latest/download"

if ! command -v npm >/dev/null 2>&1; then
  echo "redstamp needs Node.js >= 20 (npm not found) - https://nodejs.org" >&2
  exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "redstamp checks the release's provenance with the GitHub CLI (gh not found) - https://cli.github.com" >&2
  exit 1
fi

DIR=$(mktemp -d)
trap 'rm -rf "$DIR"' EXIT
TGZ="$DIR/redstamp.tgz"

echo "downloading redstamp from $BASE"
curl -fsSL -o "$TGZ" "$BASE/redstamp.tgz"
curl -fsSL -o "$TGZ.sigstore.json" "$BASE/redstamp.tgz.sigstore.json"

echo "checking its provenance"
gh attestation verify "$TGZ" --repo askalf/redstamp --bundle "$TGZ.sigstore.json"

npm install -g "$TGZ"
echo
npm ls -g --depth=0 @askalf/redstamp || true
echo "done - try: redstamp init"
