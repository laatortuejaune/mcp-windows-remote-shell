import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, writeFile, readFile, readdir, realpath, rm, stat, chmod, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { OperatorManager, initializeOperatorState, readOperatorState, PACKAGE_FILES } from '../dist/operator.js';
const origin = 'https://relay.example.com';
const uuid = '11111111-2222-3333-4444-555555555555';
const boot = '68a47246-42ef-4bf2-bb3d-e0c113adfe55';
async function fixture(t, options = {}) {
  const root = await mkdtemp(join(await realpath(tmpdir()), 'relay-operator-')); await chmod(root, 0o700);
  t.after(() => rm(root, { recursive: true, force: true }));
  const source = join(root, 'source'); const mount = join(root, 'volume'); const pkg = join(mount, 'relay'); const privateDir = join(root, 'private'); const path = join(privateDir, 'operator.json');
  await Promise.all([mkdir(source), mkdir(mount), mkdir(privateDir, { mode: 0o700 })]); await mkdir(pkg);
  for (const name of [...PACKAGE_FILES, 'cloudflared.exe']) await writeFile(join(source, name), `trusted:${name}`);
  await writeFile(join(pkg, 'cloudflared.exe'), 'evil binary'); await writeFile(join(pkg, 'notes.txt'), 'user data');
  await writeFile(join(pkg, 'rendezvous.json'), JSON.stringify({ url: 'https://evil.example', provision_key: 'stolen' }));
  await initializeOperatorState(path, { version: 2, rendezvous_url: origin, provision_key: 'a'.repeat(64), package: { directory: pkg, volume_uuid: uuid, source_directory: source } });
  let present = true; let incarnation = boot + ':123'; let remote; const posts = []; let dropResponse = false;
  const request = async (url, init) => {
    assert.equal(url, origin + '/ticket'); assert.equal(init.redirect, 'error'); assert.equal(init.headers.Authorization, 'Bearer ' + 'a'.repeat(64));
    if (init.method === 'GET') return remote ? Response.json(remote) : new Response(null, { status: 404 });
    const body = JSON.parse(init.body); posts.push(body);
    // Local intent must already block the previous session before publication.
    const state = await readOperatorState(path); assert.equal(state.expected_ticket_id, body.ticket_id); assert.ok(state.preparation);
    if (remote && body.generation <= remote.generation && body.ticket_id !== remote.ticket_id) return new Response(null, { status: 409 });
    remote = { ticket_id: body.ticket_id, generation: body.generation, expires_at: body.expires_at, status: 'pending' };
    if (dropResponse) { dropResponse = false; throw new Error('secret network details'); }
    return Response.json(remote);
  };
  const config = { fetch: request, volumeProbe: async () => present ? { uuid, mountPoint: mount, external: true, writable: true, incarnation } : null, ...options };
  return { root, path, source, mount, pkg, posts, config, manager: () => new OperatorManager(path, origin, config), present: (value) => { present = value; }, incarnation: (value) => { incarnation = value; }, status: (value) => { remote.status = value; }, drop: () => { dropResponse = true; } };
}
async function target(f) {
  const state = await readOperatorState(f.path);
  return { ticket_id: state.expected_ticket_id, url: 'https://test.trycloudflare.com', token: 'b'.repeat(64), host: 'PC', os: 'windows', session_id: 'c'.repeat(32), published_at: new Date().toISOString(), expires_at: new Date(Date.now() + 3600000).toISOString() };
}
test('fresh preparation overwrites every executable from trusted sources, preserves unknown archived files, and exposes no provisioning key', async (t) => {
  const f = await fixture(t); await f.manager().prepare();
  for (const name of [...PACKAGE_FILES, 'cloudflared.exe']) assert.equal(await readFile(join(f.pkg, name), 'utf8'), `trusted:${name}`);
  const config = JSON.parse(await readFile(join(f.pkg, 'rendezvous.json'), 'utf8')); const state = await readOperatorState(f.path);
  assert.equal(config.ticket_id, state.expected_ticket_id); assert.equal(config.ticket_secret, state.ticket.secret); assert.equal(config.version, 3); assert.equal(config.provision_key, undefined);
  assert.equal(f.posts[0].ticket_hash, createHash('sha256').update(config.ticket_secret).digest('hex'));
  const archive = (await readdir(f.mount)).find((name) => name.startsWith('relay.previous-')); assert.ok(archive);
  assert.equal(await readFile(join(f.mount, archive, 'notes.txt'), 'utf8'), 'user data'); assert.equal(await readFile(join(f.mount, archive, 'cloudflared.exe'), 'utf8'), 'evil binary');
  assert.equal((await stat(f.path)).mode & 0o777, 0o600); assert.equal((await stat(join(f.root, 'private'))).mode & 0o777, 0o700);
});
test('pins the prepared session across MCP restarts and rejects substitutions or foreign ticket IDs', async (t) => {
  const f = await fixture(t); await f.manager().prepare(); const session = await target(f);
  await f.manager().authorizeSession(session); await f.manager().authorizeSession(session);
  await assert.rejects(f.manager().authorizeSession({ ...session, token: 'd'.repeat(64) }), /session changed/);
  await assert.rejects(f.manager().authorizeSession({ ...session, ticket_id: 'e'.repeat(32) }), /configured package/);
});
test('uncertain POST retries the identical ticket and generation after restart', async (t) => {
  const f = await fixture(t); f.drop(); await assert.rejects(f.manager().prepare(), /securely/);
  const pending = await readOperatorState(f.path); assert.ok(pending.preparation); await assert.rejects(f.manager().authorizeSession(await target(f)), /configured package/);
  await f.manager().prepare(); assert.deepEqual(f.posts[0], f.posts[1]); assert.equal((await readOperatorState(f.path)).expected_ticket_id, pending.expected_ticket_id);
});
for (const phase of ['intent', 'registered', 'archived', 'installed']) test(`crash after ${phase} resumes the same durable intent with freshly rebuilt files`, async (t) => {
  const f = await fixture(t); let crash = true;
  const manager = new OperatorManager(f.path, origin, { ...f.config, afterPhase: async (current) => { if (current === phase && crash) { crash = false; throw new Error('crash'); } } });
  await assert.rejects(manager.prepare()); const pending = await readOperatorState(f.path); assert.ok(pending.preparation);
  await writeFile(join(f.source, 'cloudflared.exe'), 'updated trusted binary'); await f.manager().prepare();
  const final = await readOperatorState(f.path); assert.equal(final.expected_ticket_id, pending.expected_ticket_id); assert.equal(final.preparation, undefined);
  assert.equal(await readFile(join(f.pkg, 'cloudflared.exe'), 'utf8'), 'updated trusted binary'); assert.equal(f.posts.length, 1);
});
test('rejects unknown volume identity and symlinks in package, source, and state', async (t) => {
  const f = await fixture(t); const foreign = new OperatorManager(f.path, origin, { ...f.config, volumeProbe: async () => ({ uuid: 'a'.repeat(32), mountPoint: f.mount, external: true, writable: true }) });
  await assert.rejects(foreign.prepare(), /trusted writable/); assert.equal(f.posts.length, 0);
  await rm(join(f.source, 'cloudflared.exe')); await symlink(join(f.source, 'README.txt'), join(f.source, 'cloudflared.exe')); await assert.rejects(f.manager().prevalidate(), /symbolic/);
  await rm(join(f.source, 'cloudflared.exe')); await writeFile(join(f.source, 'cloudflared.exe'), 'good');
  await rm(f.pkg, { recursive: true }); await symlink(f.source, f.pkg); await assert.rejects(f.manager().prepare(), /symbolic/);
  const stateLink = join(f.root, 'private', 'link.json'); await symlink(f.path, stateLink); await assert.rejects(readOperatorState(stateLink), /symbolic/);
});
test('unsafe state permissions, oversized state, and reinitialization fail closed', async (t) => {
  const f = await fixture(t); const value = await readOperatorState(f.path); await assert.rejects(initializeOperatorState(f.path, value), /never overwritten/);
  await chmod(f.path, 0o644); await assert.rejects(f.manager().prepare(), /protected/); await chmod(f.path, 0o600);
  await writeFile(f.path, ' '.repeat(65537)); await assert.rejects(readOperatorState(f.path), /protected/);
});
test('process-death recovery ignores PID reuse and only removes a stale uniquely named bakery claim', async (t) => {
  const f = await fixture(t); const locks = f.path + '.locks'; await mkdir(locks, { mode: 0o700 });
  const name = 'f'.repeat(32); await writeFile(join(locks, name), JSON.stringify({ pid: process.pid, start: 'previous process incarnation', number: 1, choosing: true, name }), { mode: 0o600 });
  await f.manager().prepare(); assert.equal((await readdir(locks)).length, 0);
});
function childRun(f, extra = '') {
  const module = new URL('../dist/operator.js', import.meta.url).href;
  const code = `import {OperatorManager} from ${JSON.stringify(module)};
const opts = {volumeProbe:async()=>({uuid:${JSON.stringify(uuid)},mountPoint:${JSON.stringify(f.mount)},external:true,writable:true,incarnation:${JSON.stringify(boot + ':123')}}),fetch:async(url,init)=>{if(init.method==='GET')return new Response(null,{status:404});const b=JSON.parse(init.body);return Response.json({ticket_id:b.ticket_id,generation:b.generation,expires_at:b.expires_at,status:'pending'});}};
${extra}
await new OperatorManager(${JSON.stringify(f.path)},${JSON.stringify(origin)},opts).prepare();process.stdout.write('prepared');`;
  const child = spawn(process.execPath, ['--input-type=module', '-e', code], { stdio: ['ignore', 'pipe', 'pipe'] });
  let output = ''; let errors = ''; child.stdout.setEncoding('utf8'); child.stdout.on('data', (chunk) => { output += chunk; }); child.stderr.setEncoding('utf8'); child.stderr.on('data', (chunk) => { errors += chunk; });
  return { child, finished: new Promise((done, reject) => { child.on('error', reject); child.on('close', (status, signal) => status === 0 ? done(output) : reject(new Error(`child ended ${status ?? signal}: ${errors}`))); }) };
}
test('a killed preparation process leaves a recoverable intent and stale lock', async (t) => {
  const f = await fixture(t); const run = childRun(f, "opts.afterPhase=async(phase)=>{if(phase==='intent'){process.stdout.write('crash-ready');await new Promise(()=>{});}};");
  run.finished.catch(() => {}); t.after(() => run.child.kill());
  await new Promise((done, reject) => { const timer = setTimeout(() => reject(new Error('child readiness timeout')), 10000); run.child.stdout.on('data', (chunk) => { if (chunk.includes('crash-ready')) { clearTimeout(timer); done(); } }); });
  const before = await readOperatorState(f.path); run.child.kill('SIGKILL'); await assert.rejects(run.finished);
  await f.manager().prepare(); assert.equal((await readOperatorState(f.path)).expected_ticket_id, before.expected_ticket_id);
  assert.equal((await readdir(f.path + '.locks')).length, 0);
});
test('a mismatched ticket receipt cannot expose a freshly trusted package', async (t) => {
  const f = await fixture(t); const bad = new OperatorManager(f.path, origin, { ...f.config, fetch: async (url, init) => {
    if (init.method === 'GET') return new Response(null, { status: 404 }); const body = JSON.parse(init.body);
    return Response.json({ ticket_id: 'f'.repeat(32), generation: body.generation, expires_at: body.expires_at, status: 'pending' });
  } });
  await assert.rejects(bad.prepare(), /receipt/); assert.equal(await readFile(join(f.pkg, 'cloudflared.exe'), 'utf8'), 'evil binary');
  assert.equal((await readOperatorState(f.path)).preparation.phase, 'created');
});
test('dispatch starts under the trust lock and releases it before command completion', async (t) => {
  const f = await fixture(t); await f.manager().prepare(); const session = await target(f);
  let complete; let started; const start = new Promise((done) => { started = done; });
  const pending = f.manager().dispatchAuthorized(session, () => { started(); return new Promise((done) => { complete = done; }); });
  await start;
  await Promise.race([f.manager().prepare({ force: true }), new Promise((_, reject) => setTimeout(() => reject(new Error('command held trust lock')), 5000))]);
  await assert.rejects(f.manager().dispatchAuthorized(session, async () => { throw new Error('must not be sent'); }), /configured package/);
  complete('done'); assert.equal(await pending, 'done');
});
test('dispatch error has an attached rejection handler while the lock releases', async (t) => {
  const f = await fixture(t); await f.manager().prepare(); const session = await target(f);
  await assert.rejects(f.manager().dispatchAuthorized(session, () => Promise.reject(new Error('command failed'))), /command failed/);
  await f.manager().authorizeSession(session);
});

test('persistent export keeps the same credential after years and never starts a watcher', async t => {
  const f = await fixture(t); await f.manager().prepare(); const original = await readOperatorState(f.path);
  assert.equal(original.ticket.expires_at, null); assert.equal(original.version, 3);
  const session = { ...await target(f), sequence: 1 }; await f.manager().authorizeSession(session);
  await new OperatorManager(f.path, origin, { ...f.config, now: () => Date.now()+20*365*86400000 }).prepare();
  const copied = await readOperatorState(f.path);
  assert.deepEqual(copied.ticket, original.ticket); assert.equal(copied.expected_ticket_id, original.expected_ticket_id);
  assert.ok(copied.pinned_identity); assert.equal(f.manager().startWatching, undefined); assert.equal(f.manager().observeVolume, undefined);
  assert.equal(JSON.parse(await readFile(join(f.pkg, 'rendezvous.json'))).expires_at, null);
});
test('automatic successive sessions use increasing server sequences and reject rollback or active mutation', async t => {
  const f=await fixture(t); await f.manager().prepare(); const one={...await target(f),sequence:1};
  await f.manager().authorizeSession(one);
  const two={...one,sequence:2,session_id:'d'.repeat(32),token:'e'.repeat(64)};
  await f.manager().authorizeSession(two); await f.manager().authorizeSession(two);
  await assert.rejects(f.manager().authorizeSession(one), /replayed/);
  await assert.rejects(f.manager().authorizeSession({...two,url:'https://evil.trycloudflare.com'}), /replayed/);
  await assert.rejects(f.manager().authorizeSession({...one,sequence:undefined}), /replayed/);
  f.present(false); const offline=new OperatorManager(f.path,origin,{fetch:()=>{throw Error('must not provision');},volumeProbe:()=>{throw Error('must not inspect export storage');}});
  await offline.authorizeSession(two); assert.equal(f.posts.length,1);
});
test('explicit rotation alone changes the credential and rejects previous sessions', async t => {
  const f=await fixture(t);await f.manager().prepare();const old=await target(f);const before=await readOperatorState(f.path);
  await f.manager().prepare({force:true});const after=await readOperatorState(f.path);
  assert.notEqual(after.ticket.secret,before.ticket.secret);assert.equal(after.ticket.generation,2);
  await assert.rejects(f.manager().authorizeSession(old),/configured package/);
});
test('v2 migration preserves an already pinned session while making its credential persistent', async t => {
  const f=await fixture(t); await f.manager().prepare(); const old=await target(f);await f.manager().authorizeSession(old);
  const before=await readOperatorState(f.path);const legacy={...before,version:2,ticket:{...before.ticket,expires_at:'2026-09-06T00:00:00.000Z'}};
  await writeFile(f.path,JSON.stringify(legacy),{mode:0o600});await f.manager().prepare();const after=await readOperatorState(f.path);
  assert.equal(after.ticket.secret,before.ticket.secret);assert.equal(after.ticket.generation,before.ticket.generation);
  assert.equal(after.pinned_identity,before.pinned_identity);assert.equal(after.ticket.expires_at,null);
  await f.manager().authorizeSession(old);
  await f.manager().authorizeSession({...old,sequence:1,session_id:'d'.repeat(32)});
});
test('two processes manually copying a package retain one credential', async t => {
 const f=await fixture(t);const first=childRun(f),second=childRun(f);t.after(()=>{first.child.kill();second.child.kill();});
 assert.deepEqual(await Promise.all([first.finished,second.finished]),['prepared','prepared']);
 assert.equal((await readOperatorState(f.path)).ticket.generation,1);
});

test('ordinary local export does not require a removable volume or hardware probe', async t => {
 const f=await fixture(t);const state=await readOperatorState(f.path);delete state.package.volume_uuid;
 await writeFile(f.path,JSON.stringify(state),{mode:0o600});
 const manager=new OperatorManager(f.path,origin,{...f.config,volumeProbe:async()=>{throw Error('must not inspect hardware');}});
 await manager.prepare();assert.equal((await readOperatorState(f.path)).ticket.expires_at,null);
 assert.ok((await readFile(join(f.pkg,'start-relay.cmd'))).length);
});
test('local export cannot archive the operator credential directory', async t => {
 const f=await fixture(t);const state=await readOperatorState(f.path);delete state.package.volume_uuid;
 state.package.directory=f.root;await writeFile(f.path,JSON.stringify(state),{mode:0o600});
 await assert.rejects(f.manager().prepare(),/private operator state/);assert.equal(f.posts.length,0);
});
