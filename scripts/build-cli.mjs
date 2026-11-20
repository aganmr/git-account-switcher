// Builds the gas-cli binary into src-tauri/binaries/ so the Tauri build
// script can bundle it (see bundle.resources in tauri.conf.json).
//
// Tauri validates resource paths at compile time — before any cargo build
// runs — so the file must already exist. This script bootstraps a
// placeholder on a clean checkout, builds the real release binary, and
// drops it into place. The placeholder is gitignored and is always
// replaced before bundling, so it can never ship.
import { execFileSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

// The script lives in <root>/scripts/, so go up one level.
const root = dirname(dirname(fileURLToPath(import.meta.url)));
const srcTauri = join(root, "src-tauri");
const binDir = join(srcTauri, "binaries");
const binPath = join(binDir, "gas-cli.exe");

if (!existsSync(binPath)) {
  mkdirSync(binDir, { recursive: true });
  writeFileSync(binPath, "placeholder — replaced by `npm run build:cli`\n");
  console.log("[build:cli] created placeholder gas-cli.exe");
}

console.log("[build:cli] cargo build --release --bin gas-cli");
execFileSync("cargo", ["build", "--release", "--bin", "gas-cli"], {
  cwd: srcTauri,
  stdio: "inherit",
});

copyFileSync(join(srcTauri, "target", "release", "gas-cli.exe"), binPath);
console.log("[build:cli] release gas-cli.exe staged in src-tauri/binaries/");
