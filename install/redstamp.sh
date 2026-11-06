#!/bin/sh
# redstamp - own your agent security - https://github.com/askalf/redstamp
#
# Installs the redstamp CLI globally from the signed GitHub release tarball.
# Prefer to verify before you run? Same artifact, same bytes:
#   curl -fsSLO https://github.com/askalf/redstamp/releases/latest/download/redstamp.tgz
#   gh attestation verify redstamp.tgz --owner askalf
#   npm i -g ./redstamp.tgz
set -eu

URL="https://github.com/askalf/redstamp/releases/latest/download/redstamp.tgz"

if ! command -v npm >/dev/null 2>&1; then
  echo "redstamp needs Node.js >= 20 (npm not found) - https://nodejs.org" >&2
  exit 1
fi

echo "installing redstamp from $URL"
npm install -g "$URL"
echo
npm ls -g --depth=0 @askalf/redstamp || true
echo "done - try: redstamp init"
