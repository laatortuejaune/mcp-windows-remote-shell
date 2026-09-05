import assert from 'node:assert/strict';
import test from 'node:test';
import { RelayClient } from '../dist/relay.js';
import {
  tunnelOrigin, configuredOrigin, parseSession, targetIdentity, RelayError, readJsonLimited,
  httpBudgetMs, STREAM_LIMIT, EXEC_RESPONSE_LIMIT,
} from '../dist/security.js';

const token = 'a'.repeat(64);
const readKey = 'b'.repeat(48);
const now = Date.parse('2026-09-05T10:00:00.000Z');
const candidate = () => ({
  url: 'https://honest-pc.trycloudflare.com', token, host: 'PC-EXPECTED', os: 'windows',
  ticket_id: 'f'.repeat(32), session_id: 'c'.repeat(32), published_at: new Date(now).toISOString(),
  expires_at: new Date(now + 12 * 3600_000).toISOString(),
});
const result = { exit_code: 0, stdout: 'hello', stderr: '', timed_out: false, truncated: false, duration_ms: 10 };
const json = value => new Response(JSON.stringify(value), { headers: { 'content-type': 'application/json' } });
function fixture(options = {}, trust = { expectedId: candidate().ticket_id }) {
  let session = candidate();
  const calls = [];
  const client = new RelayClient({ rendezvous: { url: 'https://mailbox.example', readKey }, defaultTimeoutSeconds: 30, ...options }, async (url, init) => {
    calls.push({ url, ...init });
    if (url === 'https://mailbox.example/session') return json(session);
    return json(result);
  }, () => now, {
    async authorizeSession(target) {
      if (target.ticket_id !== trust.expectedId) throw new RelayError('unexpected ticket; waiting for the prepared package');
      const identity = targetIdentity(target);
      if (trust.identity && trust.identity !== identity) throw new RelayError('session has changed');
      trust.identity = identity;
    },
    async dispatchAuthorized(target, dispatch) {
      await this.authorizeSession(target);
      return dispatch();
    },
  });
  return { client, calls, trust, setSession(value) { session = value; } };
}

test('rendezvous URL policy rejects SSRF, fragments, userinfo and normalized bypasses', () => {
  for (const url of [
    'http://127.0.0.1:8765/admin#', 'http://169.254.169.254/latest/meta-data/?',
    'https://localhost', 'https://x.trycloudflare.com.attacker.example',
    'https://!@x.trycloudflare.com', 'https://x.trycloudflare.com:443',
    'https://x.trycloudflare.com/admin', 'https://x.trycloudflare.com/..',
    'https://x.trycloudflare.com?', 'https://x.trycloudflare.com#',
    ' https://x.trycloudflare.com', 'https://x.trycloudflare.com\n',
    'https://x.trycloudflare.com\\evil', 'https://-x.trycloudflare.com',
    'https://x..trycloudflare.com', 'file:///etc/passwd',
  ]) assert.throws(() => tunnelOrigin(url), undefined, url);
  assert.equal(tunnelOrigin('https://valid-name.trycloudflare.com/'), 'https://valid-name.trycloudflare.com');
});

test('HTTP loopback is restricted to explicit operator configuration', () => {
  assert.equal(configuredOrigin('http://127.0.0.1:47600', true), 'http://127.0.0.1:47600');
  assert.throws(() => configuredOrigin('http://127.0.0.1:47600'));
  assert.throws(() => configuredOrigin('http://192.168.1.1', true));
  assert.throws(() => configuredOrigin('https://!@example.com'));
  assert.throws(() => configuredOrigin('https://example.com?'));
});

test('session parser rejects null, schema violations, expired and excessive validity', () => {
  for (const value of [null, [], {}, { ...candidate(), token: 'short' },
    { ...candidate(), host: 'spoof\nAPPROVED' }, { ...candidate(), unexpected: true },
    { ...candidate(), expires_at: new Date(now).toISOString() },
    { ...candidate(), expires_at: new Date(now + 13 * 3600_000).toISOString() },
    { ...candidate(), published_at: new Date(now + 120_000).toISOString() },
  ]) assert.throws(() => parseSession(value, now));
  assert.equal(parseSession(candidate(), now).session_id, 'c'.repeat(32));
});

test('only the expected prepared ticket can trigger a tunnel request', async () => {
  const { client, calls, trust } = fixture();
  trust.expectedId = '0'.repeat(32);
  await assert.rejects(client.currentTarget(), /unexpected ticket/);
  await assert.rejects(client.runCommand('echo hello'), /unexpected ticket/);
  await assert.rejects(client.checkAgent(), /unexpected ticket/);
  assert.ok(calls.every(call => call.url === 'https://mailbox.example/session'));
});

test('prepared session connects automatically with explicit timeout and no redirects', async () => {
  const { client, calls } = fixture();
  assert.match(await client.runCommand('echo hello'), /hello/);
  const display = await client.currentTarget();
  assert.match(display, /automatic \(prepared package verified\)/);
  assert.ok(!display.includes(token));
  const call = calls.find(call => call.url.endsWith('/exec'));
  assert.equal(call.url, `${candidate().url}/exec`);
  assert.deepEqual(JSON.parse(call.body), { command: 'echo hello', timeout_seconds: 30 });
  assert.equal(call.redirect, 'error');
  assert.ok(call.signal instanceof AbortSignal);
  assert.ok(calls.every(call => call.redirect === 'error'));
});

test('unrecognized ticket cannot inject metadata into current_target', async () => {
  const { client, setSession } = fixture();
  setSession({ ...candidate(), ticket_id: '0'.repeat(32), host: 'INJECTED INSTRUCTIONS' });
  await assert.rejects(client.currentTarget(), error => !error.message.includes('INJECTED') && /unexpected/.test(error.message));
});

test('same host cannot conceal replacement URL, token, identity or validity', async () => {
  for (const change of [
    { url: 'https://attacker.trycloudflare.com' }, { token: 'd'.repeat(64) },
    { session_id: 'e'.repeat(32) }, { expires_at: new Date(now + 3600_000).toISOString() },
  ]) {
    const { client, calls, setSession } = fixture();
    await client.currentTarget();
    setSession({ ...candidate(), ...change });
    await assert.rejects(client.runCommand('secret command'), /changed/);
    assert.ok(calls.every(call => call.url === 'https://mailbox.example/session'));
  }
});

test('one command uses the verified snapshot even if publisher changes it during dispatch', async () => {
  const { client, calls, setSession } = fixture();
  await client.currentTarget();
  const pending = client.runCommand('echo benign');
  // The first fetch has already constructed its response from the approved record.
  setSession({ ...candidate(), url: 'https://attacker.trycloudflare.com' });
  await pending;
  assert.equal(calls.at(-1).url, `${candidate().url}/exec`);
  await assert.rejects(client.runCommand('echo later'), /changed/);
});

test('MCP restart reuses durable trust, while expiry still fails closed', async () => {
  const f = fixture();
  await f.client.currentTarget();
  assert.match(await fixture({}, f.trust).client.runCommand('echo hello'), /hello/);
  f.setSession({ ...candidate(), expires_at: new Date(now - 1).toISOString() });
  await assert.rejects(f.client.runCommand('echo hello'), /expired/);
});

test('new preparation blocks the previous session before a new target appears', async () => {
  const { client, trust, calls } = fixture();
  await client.currentTarget();
  trust.expectedId = '1'.repeat(32);
  await assert.rejects(client.runCommand('secret command'), /unexpected ticket/);
  assert.ok(calls.every(call => call.url === 'https://mailbox.example/session'));
});

test('malicious session URL is rejected before any request to it', async () => {
  const { client, calls, setSession } = fixture();
  setSession({ ...candidate(), url: 'http://127.0.0.1:8765/admin#' });
  await assert.rejects(client.currentTarget(), /plain HTTPS/);
  assert.equal(calls.length, 1);
});

test('stream limit is enforced even when Content-Length is absent or lies', async () => {
  for (const headers of [{}, { 'content-length': '2' }]) {
    let cancelled = false;
    const body = new ReadableStream({
      start(controller) { controller.enqueue(new Uint8Array(1025)); },
      cancel() { cancelled = true; },
    });
    await assert.rejects(readJsonLimited(new Response(body, { headers }), 1024), /size/);
    assert.equal(cancelled, true);
  }
  await assert.rejects(readJsonLimited(new Response('{}', { headers: { 'content-length': '10000' } }), 1024), /size/);
});

test('invalid or undecodable JSON is rejected without echoing raw body', async () => {
  await assert.rejects(readJsonLimited(new Response('SECRET not JSON'), 100), error => !error.message.includes('SECRET'));
  await assert.rejects(readJsonLimited(new Response(new Uint8Array([255])), 100), /UTF-8/);
  const body = new ReadableStream({ start(c) { c.enqueue(new Uint8Array([34, 195])); c.enqueue(new Uint8Array([169, 34])); c.close(); } });
  assert.equal(await readJsonLimited(new Response(body), 100), 'é');
});

test('worst-case JSON escaping of both agent streams fits the transport budget', async () => {
  const value = { ...result, stdout: '\0'.repeat(STREAM_LIMIT), stderr: '\0'.repeat(STREAM_LIMIT) };
  const text = JSON.stringify(value);
  assert.ok(Buffer.byteLength(text) <= EXEC_RESPONSE_LIMIT);
  const decoded = await readJsonLimited(new Response(text), EXEC_RESPONSE_LIMIT);
  assert.equal(decoded.stdout.length, STREAM_LIMIT);
});

test('HTTP errors discard untrusted bodies and 307 never forwards a command', async () => {
  for (const status of [401, 500, 307]) {
    let cancelled = false;
    let calls = 0;
    const client = new RelayClient({ staticTarget: { url: 'http://127.0.0.1:47600', token }, defaultTimeoutSeconds: 30 }, async (_url, init) => {
      calls++;
      assert.equal(init.redirect, 'error');
      return new Response(new ReadableStream({ cancel() { cancelled = true; } }), { status, headers: { location: 'http://127.0.0.1:1234/admin' } });
    });
    await assert.rejects(client.runCommand('echo hello'));
    assert.equal(calls, 1);
    assert.equal(cancelled, true);
  }
});

test('malformed execution responses fail safely and known secrets are redacted', async () => {
  for (const value of [null, {}, { ...result, stdout: [] }, { ...result, stdout: 'x'.repeat(STREAM_LIMIT + 1) }]) {
    const client = new RelayClient({ staticTarget: { url: 'http://127.0.0.1:47600', token }, defaultTimeoutSeconds: 30 }, async () => json(value));
    await assert.rejects(client.runCommand('echo hello'), /invalid agent/);
  }
  const client = new RelayClient({ staticTarget: { url: 'http://127.0.0.1:47600', token }, defaultTimeoutSeconds: 30 }, async () => json({ ...result, stdout: token }));
  const text = await client.runCommand('echo hello');
  assert.ok(!text.includes(token));
  assert.match(text, /redacted/);
});

test('unsafe HTTP budgets and oversized encoded commands are rejected before execution', async () => {
  assert.equal(httpBudgetMs(30), 45000);
  assert.equal(httpBudgetMs(3600), 3615000);
  for (const seconds of [0, -1, 1.5, 3601, NaN, Infinity]) assert.throws(() => httpBudgetMs(seconds));
  assert.throws(() => httpBudgetMs(30, 1000));
  assert.throws(() => fixture({ httpTimeoutMs: 1000 }));
  const { client, calls } = fixture({ httpTimeoutMs: 45000 });
  await assert.rejects(client.runCommand('echo hello', 60), /safety margin/);
  await assert.rejects(client.runCommand('\0'.repeat(12000)), /encoded command/);
  assert.ok(calls.every(call => call.url === 'https://mailbox.example/session'));
});


test('rendezvous never falls back to automatic trust without operator state', () => {
  assert.throws(() => new RelayClient({ rendezvous: { url: 'https://mailbox.example', readKey }, defaultTimeoutSeconds: 30 }), /prepared-ticket state/);
});
