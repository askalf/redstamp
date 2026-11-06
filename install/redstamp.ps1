# redstamp - own your agent security - https://github.com/askalf/redstamp
#
# Installs the redstamp CLI globally from the signed GitHub release tarball. The tarball is
# downloaded, its provenance is checked with gh, and only that checked file reaches npm: a failed
# check installs nothing. The same steps by hand:
#   gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'
#   gh attestation verify redstamp.tgz --repo askalf/redstamp --bundle redstamp.tgz.sigstore.json
#   npm i -g ./redstamp.tgz
$ErrorActionPreference = 'Stop'

$base = 'https://github.com/askalf/redstamp/releases/latest/download'

if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
  throw 'redstamp needs Node.js >= 20 (npm not found) - https://nodejs.org'
}
if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
  throw "redstamp checks the release's provenance with the GitHub CLI (gh not found) - https://cli.github.com"
}

$dir = Join-Path ([IO.Path]::GetTempPath()) ('redstamp-' + [guid]::NewGuid())
New-Item -ItemType Directory -Path $dir | Out-Null
try {
  $tgz = Join-Path $dir 'redstamp.tgz'
  $bundle = "$tgz.sigstore.json"

  Write-Host "downloading redstamp from $base"
  Invoke-WebRequest -UseBasicParsing -Uri "$base/redstamp.tgz" -OutFile $tgz
  Invoke-WebRequest -UseBasicParsing -Uri "$base/redstamp.tgz.sigstore.json" -OutFile $bundle

  # A native command's exit status never stops the script on its own, so the check and the install
  # are tested here. The listing after them is best effort, as in the sh installer.
  Write-Host 'checking its provenance'
  gh attestation verify $tgz --repo askalf/redstamp --bundle $bundle
  if ($LASTEXITCODE -ne 0) { throw 'the provenance check failed: nothing was installed' }

  npm install -g $tgz
  if ($LASTEXITCODE -ne 0) { throw "npm install failed with exit code $LASTEXITCODE" }

  npm ls -g --depth=0 '@askalf/redstamp'
  Write-Host 'done - try: redstamp init'
} finally {
  Remove-Item -Recurse -Force $dir -ErrorAction SilentlyContinue
}
