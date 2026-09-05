#!/usr/bin/env node
import { randomBytes } from 'node:crypto';
import { mkdir, lstat, writeFile } from 'node:fs/promises';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { configuredOrigin } from '../mcp-server/dist/security.js';
import { initializeOperatorState, defaultOperatorStatePath } from '../mcp-server/dist/operator.js';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export async function setupOperator({ rendezvousUrl, packageDirectory, stateDirectory = dirname(defaultOperatorStatePath()) }) {
  const url = configuredOrigin(rendezvousUrl);
  const directory = resolve(stateDirectory);
  if (directory === root || directory.startsWith(root + '/')) throw Error('Store operator credentials outside the source checkout.');
  for (let p = directory;; p = dirname(p)) {
    try { if ((await lstat(p)).isSymbolicLink()) throw Error('Credential paths must not contain symbolic links.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
    if (p === dirname(p)) break;
  }
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if ((info.mode & 0o077) || info.uid !== process.getuid()) throw Error('Use a private directory owned by the current user (mode 0700).');
  const files = ['operator.json', 'worker-secrets.json', 'mcp-config.json'].map(name => join(directory, name));
  for (const p of files) {
    try { await lstat(p); throw Error('Configuration already exists; setup never replaces credentials.'); }
    catch (error) { if (error.code !== 'ENOENT') throw error; }
  }
  const provisionKey = randomBytes(32).toString('hex');
  const readKey = randomBytes(24).toString('hex');
  const output = resolve(packageDirectory);
  if (directory === output || directory.startsWith(output + "/")) throw Error("Package output must not contain operator credentials.");
  await initializeOperatorState(files[0], {
    version: 3, rendezvous_url: url, provision_key: provisionKey,
    package: { directory: output, source_directory: join(root, 'target-windows') },
  });
  await writeFile(files[1], JSON.stringify({ READ_KEY: readKey, PROVISION_KEY: provisionKey }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  await writeFile(files[2], JSON.stringify({ mcpServers: { relay: {
    command: process.execPath, args: [join(root, 'mcp-server/dist/index.js')], env: {
      RELAY_RENDEZVOUS_URL: url, RELAY_RENDEZVOUS_READ_KEY: readKey, RELAY_OPERATOR_STATE: files[0],
    },
  } } }, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
  return { directory, packageDirectory: output };
}
async function main() {
  const args = process.argv.slice(2); const options = {};
  const fields = { '--rendezvous-url': 'rendezvousUrl', '--package-dir': 'packageDirectory', '--state-dir': 'stateDirectory' };
  for (let i = 0; i < args.length; i++) {
    const field = fields[args[i]];
    if (!field || !args[i + 1]) throw Error('Usage: setup-operator.mjs --rendezvous-url HTTPS_ORIGIN --package-dir DIRECTORY [--state-dir PRIVATE_DIRECTORY]');
    options[field] = args[++i];
  }
  if (!options.rendezvousUrl || !options.packageDirectory) throw Error('A rendezvous URL and package directory are required.');
  const result = await setupOperator(options);
  process.stdout.write(`Private configuration created in ${result.directory}\nUpload worker-secrets.json to your Worker, then configure your MCP client from mcp-config.json.\nCreate the package parent directory and run the package exporter. No credential values were printed.\n`);
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => { process.stderr.write('Setup failed. Check the arguments, private directory permissions, and existing configuration. Existing credentials are never overwritten.\n'); process.exitCode = 1; });
}
