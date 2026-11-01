#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');
const { installBinary, BK_BIN_PATH } = require('./install-binary');

function findBinary() {
  if (fs.existsSync(BK_BIN_PATH)) {
    try {
      fs.accessSync(BK_BIN_PATH, fs.constants.X_OK);
      return BK_BIN_PATH;
    } catch {}
  }

  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  const searchPaths = [
    path.join(__dirname, 'bk'),
    path.join(__dirname, 'bug-killer'),
    path.join(homeDir, '.local', 'bin', 'bk'),
    path.join(homeDir, '.cargo', 'bin', 'bk'),
    path.join(homeDir, '.local', 'bin', 'bug-killer'),
    path.join(homeDir, '.cargo', 'bin', 'bug-killer'),
    path.join(__dirname, '..', 'target', 'release', 'bk'),
    path.join(__dirname, '..', 'target', 'release', 'bug-killer'),
  ];

  for (const p of searchPaths) {
    if (fs.existsSync(p)) {
      try {
        fs.accessSync(p, fs.constants.X_OK);
        return p;
      } catch {}
    }
  }

  // Attempt dynamic on-the-fly provisioning
  installBinary();
  if (fs.existsSync(BK_BIN_PATH)) {
    return BK_BIN_PATH;
  }

  return null;
}

const bin = findBinary();
if (!bin) {
  console.error('[bug-killer] Error: Could not locate or provision native bk binary.');
  console.error('[bug-killer] Please run: curl -fsSL https://raw.githubusercontent.com/imMamdouhaboammar/bug-killer/master/scripts/install.sh | bash');
  console.error('[bug-killer] Or: cargo install --path .');
  process.exit(1);
}

const result = spawnSync(bin, process.argv.slice(2), {
  stdio: 'inherit',
  env: process.env,
});

if (result.error) {
  console.error(`[bug-killer] Execution error: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
} else {
  process.exit(result.status ?? 0);
}
