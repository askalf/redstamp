// This package is a pointer, not redstamp. Importing it should fail loudly
// with directions rather than with a cryptic module-resolution error.
throw new Error(
  [
    '@askalf/redstamp is not distributed on npm — this package is a pointer.',
    '',
    'Install the Sigstore-signed release instead:',
    "  gh release download --repo askalf/redstamp --pattern 'redstamp.tgz*'",
    '  gh attestation verify redstamp.tgz --owner askalf',
    '  npm i -g ./redstamp.tgz',
    '',
    'Why: https://github.com/askalf/redstamp#readme',
  ].join('\n')
);
