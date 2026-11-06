# redstamp - own your agent security - https://github.com/askalf/redstamp
#
# Installs the redstamp CLI globally from the signed GitHub release tarball,
# after verifying its Sigstore provenance. Same steps, by hand:
#   gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'
#   gh attestation verify redstamp.tgz --repo askalf/redstamp --bundle redstamp.tgz.sigstore.json
#   npm i -g ./redstamp.tgz
$ErrorActionPreference = 'Stop'

$repo = 'askalf/redstamp'

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  Write-Host 'redstamp needs Node.js >= 20 (npm not found) - https://nodejs.org'
  exit 1
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  Write-Host 'redstamp needs the GitHub CLI to verify provenance (gh not found) - https://cli.github.com'
  exit 1
}

$tmp = Join-Path ([System.IO.Path]::GetTempPath()) ('redstamp-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
$tgz = Join-Path $tmp 'redstamp.tgz'
$bundle = Join-Path $tmp 'redstamp.tgz.sigstore.json'

# Native commands do not stop on a nonzero exit under $ErrorActionPreference,
# so every one is checked through $LASTEXITCODE before the next step runs.
$failed = $null
try {
  Write-Host "downloading redstamp.tgz from the latest $repo release"
  gh release download --repo $repo --pattern redstamp.tgz --pattern redstamp.tgz.sigstore.json --dir $tmp
  if ($LASTEXITCODE -ne 0) { throw 'downloading the release assets failed' }

  # Nothing is installed unless the tarball was built and signed by this repo.
  gh attestation verify $tgz --repo $repo --bundle $bundle
  if ($LASTEXITCODE -ne 0) { throw 'provenance verification failed - not installing' }

  npm install -g $tgz
  if ($LASTEXITCODE -ne 0) { throw "npm install failed (exit $LASTEXITCODE)" }
} catch {
  $failed = $_.Exception.Message
} finally {
  Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}

if ($failed) {
  [Console]::Error.WriteLine("redstamp: $failed")
  exit 1
}

npm ls -g --depth=0 '@askalf/redstamp'
Write-Host 'done - try: redstamp init'
