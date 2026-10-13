/**
 * Vendor the scanner core of repo-inject-guard into src/vendor/oc-rig-core.
 *
 * The plugin is a thin Cordis adapter; the detection engine stays owned by the
 * repo-inject-guard repository (zero-LLM, deterministic, tested there). This
 * script copies exactly the two self-contained modules the engine needs and
 * refuses to vendor anything that grew new external imports.
 *
 * Usage: node scripts/sync-oc-rig-core.mjs [--check]
 *   --check  verify the vendored copy is in sync, change nothing (CI guard)
 */
import { copyFile, mkdir, readFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const pluginRoot = resolve(here, '..');
const sourceRoot = process.env.RIG_SRC
  ? resolve(pluginRoot, process.env.RIG_SRC)
  : resolve(pluginRoot, '..', 'repo-inject-guard', 'src');
const vendorRoot = join(pluginRoot, 'src', 'vendor', 'oc-rig-core');

/** The engine closure: applyRules (rules.ts) pulls only util.ts. */
const FILES = ['rules.ts', 'util.ts'];
/** Imports allowed inside vendored files: intra-closure + node builtins only. */
const ALLOWED_IMPORTS = new Set(['./util.js', './rules.js']);

function importsOf(source) {
  const imports = [];
  for (const line of source.split('\n')) {
    const m = /^import\s(?:type\s)?(?:[^'"]*from\s)?['"]([^'"]+)['"]/.exec(line);
    if (m) imports.push(m[1]);
  }
  return imports;
}

async function main() {
  const checkOnly = process.argv.includes('--check');
  const results = [];
  let dirty = false;

  await mkdir(vendorRoot, { recursive: true });

  for (const file of FILES) {
    const src = join(sourceRoot, file);
    if (!existsSync(src)) {
      console.error(`sync-oc-rig-core: missing source ${src}`);
      console.error('Is the repo-inject-guard checkout a sibling of this plugin?');
      process.exit(1);
    }
    const source = await readFile(src, 'utf8');

    for (const spec of importsOf(source)) {
      const ok = ALLOWED_IMPORTS.has(spec) || spec.startsWith('node:');
      if (!ok) {
        console.error(`sync-oc-rig-core: ${file} now imports "${spec}" — outside the engine closure.`);
        console.error('Extend FILES/ALLOWED_IMPORTS deliberately after reviewing that dependency.');
        process.exit(1);
      }
    }

    const dest = join(vendorRoot, file);
    const existing = existsSync(dest) ? await readFile(dest, 'utf8') : null;
    if (existing !== source) dirty = true;
    results.push({ file, changed: existing !== source });

    if (!checkOnly && existing !== source) {
      await copyFile(src, dest);
      console.log(`synced ${file}${existing === null ? ' (new)' : ' (updated)'}`);
    }
  }

  if (checkOnly) {
    if (dirty) {
      console.error('sync-oc-rig-core: vendored copy is stale; run `npm run sync`.');
      process.exit(1);
    }
    console.log('sync-oc-rig-core: vendored copy is in sync.');
  } else if (!dirty) {
    console.log('sync-oc-rig-core: already in sync.');
  }
}

main();
