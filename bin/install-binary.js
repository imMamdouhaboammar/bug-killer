#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { execSync, spawnSync } = require('child_process');

const PKG_ROOT = path.resolve(__dirname, '..');
const BIN_DIR = __dirname;
const BK_BIN_PATH = path.join(BIN_DIR, process.platform === 'win32' ? 'bk.exe' : 'bk');
const VERSION = '0.2.0';

function isExecutable(filePath) {
  try {
    fs.accessSync(filePath, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function downloadFromGithub() {
  const osMap = { darwin: 'darwin', linux: 'linux', win32: 'windows' };
  const archMap = { arm64: 'arm64', x64: 'x86_64' };
  const os = osMap[process.platform] || process.platform;
  const arch = archMap[process.arch] || process.arch;
  const assetName = `bk-${os}-${arch}${process.platform === 'win32' ? '.exe' : ''}`;
  const url = `https://github.com/imMamdouhaboammar/bug-killer/releases/download/v${VERSION}/${assetName}`;

  try {
    console.log(`[bug-killer] Fetching prebuilt release binary from GitHub Releases (${assetName})...`);
    const res = await fetch(url, { redirect: 'follow' });
    if (!res.ok) {
      return false;
    }
    const buffer = Buffer.from(await res.arrayBuffer());
    if (buffer.length < 1000) {
      return false;
    }
    fs.writeFileSync(BK_BIN_PATH, buffer);
    fs.chmodSync(BK_BIN_PATH, 0o755);
    console.log(`[bug-killer] Successfully installed ${assetName} to ${BK_BIN_PATH}`);
    return true;
  } catch (err) {
    return false;
  }
}

async function installBinary() {
  if (fs.existsSync(BK_BIN_PATH) && isExecutable(BK_BIN_PATH)) {
    return true;
  }

  // 1. Check local checkout target/release/bk
  const localRelease = path.join(PKG_ROOT, 'target', 'release', process.platform === 'win32' ? 'bk.exe' : 'bk');
  if (fs.existsSync(localRelease) && isExecutable(localRelease)) {
    try {
      fs.copyFileSync(localRelease, BK_BIN_PATH);
      fs.chmodSync(BK_BIN_PATH, 0o755);
      return true;
    } catch {}
  }

  // 2. Check if bk or bug-killer is already on PATH
  try {
    const whichRes = execSync('which bk || which bug-killer', { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
    if (whichRes && fs.existsSync(whichRes)) {
      try {
        fs.copyFileSync(whichRes, BK_BIN_PATH);
        fs.chmodSync(BK_BIN_PATH, 0o755);
        return true;
      } catch {}
    }
  } catch {}

  // 3. Check ~/.local/bin/bk or ~/.cargo/bin/bk
  const homeDir = process.env.HOME || process.env.USERPROFILE || '';
  const candidateLocations = [
    path.join(homeDir, '.local', 'bin', 'bk'),
    path.join(homeDir, '.cargo', 'bin', 'bk'),
    '/usr/local/bin/bk'
  ];
  for (const loc of candidateLocations) {
    if (fs.existsSync(loc) && isExecutable(loc)) {
      try {
        fs.copyFileSync(loc, BK_BIN_PATH);
        fs.chmodSync(BK_BIN_PATH, 0o755);
        return true;
      } catch {}
    }
  }

  // 4. Try GitHub Release download
  if (typeof fetch === 'function') {
    const downloaded = await downloadFromGithub();
    if (downloaded) {
      return true;
    }
  }

  // 5. Try compiling via Cargo if present
  try {
    const hasCargo = spawnSync('cargo', ['--version'], { stdio: 'ignore' }).status === 0;
    if (hasCargo) {
      console.log('[bug-killer] Compiling native release binary via Cargo...');
      if (fs.existsSync(path.join(PKG_ROOT, 'Cargo.toml'))) {
        execSync(`cargo build --release --bin bk`, { cwd: PKG_ROOT, stdio: 'inherit' });
        if (fs.existsSync(localRelease)) {
          fs.copyFileSync(localRelease, BK_BIN_PATH);
          fs.chmodSync(BK_BIN_PATH, 0o755);
          return true;
        }
      }
    }
  } catch {}

  // 6. Try scripts/install.sh
  const installScript = path.join(PKG_ROOT, 'scripts', 'install.sh');
  if (fs.existsSync(installScript) && process.platform !== 'win32') {
    try {
      console.log('[bug-killer] Running scripts/install.sh...');
      execSync(`bash "${installScript}" --prefix "${BIN_DIR}"`, { stdio: 'inherit' });
      if (fs.existsSync(BK_BIN_PATH)) {
        return true;
      }
    } catch {}
  }

  return false;
}

if (require.main === module) {
  installBinary().then((ok) => {
    if (!ok && !fs.existsSync(BK_BIN_PATH)) {
      console.warn('[bug-killer] Native binary provision will complete on first run or via `cargo install --path .`');
    }
  });
}

module.exports = { installBinary, BK_BIN_PATH };
