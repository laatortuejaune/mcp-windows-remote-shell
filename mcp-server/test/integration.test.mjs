import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { access } from 'node:fs/promises';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { once } from 'node:events';
import test from 'node:test';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';

const token = '9'.repeat(64);
const entrypoint = fileURLToPath(new URL('../dist/index.js', import.meta.url));
async function connect(t, url) {
  const transport = new StdioClientTransport({
    command: process.execPath, args: [entrypoint],
    env: { RELAY_URL: url, RELAY_TOKEN: token }, stderr: 'pipe',
  });
  let diagnostics = '';
  const client = new Client({ name: 'relay-security-test', version: '1.0.0' });
  t.after(async () => { await client.close(); assert.ok(!diagnostics.includes(token)); });
  await client.connect(transport);
  transport.stderr?.on('data', data => { diagnostics += data.toString(); });
  return client;
}

test('stdio integration preserves JSON-RPC and blocks real HTTP redirects', { timeout: 15000 }, async t => {
  let forbiddenHits = 0;
  let behavior = 'redirect';
  const server = createServer((req, res) => {
    req.resume();
    if (req.url === '/sink') { forbiddenHits++; res.end('{}'); return; }
    if (behavior === 'redirect') { res.writeHead(307, { location: '/sink' }); res.end(); }
    else if (behavior === 'malformed') { res.setHeader('content-type', 'application/json'); res.end('{"stdout":null}'); }
    else { res.setHeader('content-type', 'application/json'); res.end(JSON.stringify({ exit_code: 0, stdout: 'stdio works', stderr: '', timed_out: false, truncated: false, duration_ms: 1 })); }
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  t.after(async () => { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); });
  const client = await connect(t, `http://127.0.0.1:${server.address().port}`);
  const tools = await client.listTools();
  assert.deepEqual(tools.tools.map(tool => tool.name).sort(), ['check_agent', 'current_target', 'run_command']);
  const denied = await client.callTool({ name: 'run_command', arguments: { command: 'echo test' } });
  assert.equal(denied.isError, true);
  assert.equal(forbiddenHits, 0);
  behavior = 'malformed';
  const invalid = await client.callTool({ name: 'run_command', arguments: { command: 'echo test' } });
  assert.equal(invalid.isError, true);
  behavior = 'good';
  const valid = await client.callTool({ name: 'run_command', arguments: { command: 'echo test' } });
  assert.ok(!valid.isError);
  assert.match(valid.content[0].text, /stdio works/);
});

const binary = fileURLToPath(new URL('../../agent/dist/relay-agent', import.meta.url));
let available = true;
try { await access(binary); } catch { available = false; }
test('MCP to native agent executes a harmless command and removes relay secrets from child env', { skip: !available && 'build agent first with agent/build.sh', timeout: 15000 }, async t => {
  const agent = spawn(binary, ['--port', '0', '--timeout', '30'], {
    env: { PATH: process.env.PATH, RELAY_TOKEN: token, RELAY_RENDEZVOUS_READ_KEY: '8'.repeat(48) },
    stdio: ['ignore', 'ignore', 'pipe'],
  });
  t.after(async () => {
    if (agent.exitCode === null && agent.signalCode === null) {
      const exited = once(agent, 'exit');
      agent.kill('SIGTERM');
      await exited;
    }
  });
  const origin = await new Promise((resolve, reject) => {
    let output = '';
    const timer = setTimeout(() => reject(new Error('agent did not announce an ephemeral loopback port')), 5000);
    agent.once('error', error => { clearTimeout(timer); reject(error); });
    agent.once('exit', () => { clearTimeout(timer); reject(new Error('agent exited before ready')); });
    agent.stderr.on('data', data => {
      output += data.toString();
      const match = output.match(/listening on (http:\/\/127\.0\.0\.1:([1-9][0-9]*))/);
      if (match) { clearTimeout(timer); resolve(match[1]); }
    });
  });
  const client = await connect(t, origin);
  const health = await client.callTool({ name: 'check_agent', arguments: {} });
  assert.ok(!health.isError, JSON.stringify(health));
  assert.match(health.content[0].text, /default_timeout_seconds/);
  const command = 'printf "relay-integration-ok\\n"; if env | grep -q "^RELAY_"; then echo leaked-relay-environment; exit 9; fi';
  const execution = await client.callTool({ name: 'run_command', arguments: { command, timeout_seconds: 5 } });
  assert.ok(!execution.isError, JSON.stringify(execution));
  assert.match(execution.content[0].text, /exit_code=0/);
  assert.match(execution.content[0].text, /relay-integration-ok/);
  assert.ok(!execution.content[0].text.includes('leaked-relay-environment'));
});
