# redstamp - own your agent security - https://github.com/askalf/redstamp
#
# Installs the redstamp CLI globally from the signed GitHub release tarball.
# Prefer to verify before you run? Same artifact, same bytes:
#   irm https://github.com/askalf/redstamp/releases/latest/download/redstamp.tgz -OutFile redstamp.tgz
#   gh attestation verify redstamp.tgz --owner askalf
#   npm i -g ./redstamp.tgz
$ErrorActionPreference = 'Stop'

$url = 'https://github.com/askalf/redstamp/releases/latest/download/redstamp.tgz'

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  Write-Host 'redstamp needs Node.js >= 20 (npm not found) - https://nodejs.org'
  exit 1
}

Write-Host "installing redstamp from $url"
npm install -g $url
npm ls -g --depth=0 '@askalf/redstamp'
Write-Host 'done - try: redstamp init'
