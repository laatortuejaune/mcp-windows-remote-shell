import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { after, before, beforeEach, test } from "node:test";
import { Miniflare, convertV4MiniflareOptions } from "miniflare";

const digest = value => createHash("sha256").update(value).digest("hex");
const READ_KEY = "read-test-".padEnd(48, "r");
const WRITE_KEY = "write-test-".padEnd(48, "w");
const PROVISION_KEY = digest("operator-only-test-key");
const SLOT = { name: "operator-session" };
const OPTIONS = {
  name: "relay-rendezvous-test",
  modules: true,
  scriptPath: fileURLToPath(new URL("../.wrangler/build/index.js", import.meta.url)),
  compatibilityDate: "2026-09-01",
  compatibilityFlags: ["nodejs_compat"],
  durableObjects: { MAILBOX: { className: "SessionMailbox", useSQLite: true } },
  bindings: { READ_KEY, PROVISION_KEY, WRITE_KEY },
  unsafeInspectDurableObjects: true,
};
let mf;
let storage;

before(async () => {
  mf = new Miniflare(convertV4MiniflareOptions(OPTIONS));
  await mf.ready;
  await request("GET", PROVISION_KEY, undefined, {}, "/ticket");
  storage = await mf.unsafeGetDurableObjectStorage(OPTIONS.name, "SessionMailbox", SLOT);
});
beforeEach(async () => {
  await storage.exec("DELETE FROM current_session");
  await storage.exec("DELETE FROM latest_ticket");
  await storage.exec("DELETE FROM seen_sessions");
  await storage.exec("UPDATE session_counter SET value = 0");
});
after(async () => { await mf?.dispose(); });

const secret = number => digest(`publisher-ticket-${number}`);
function ticket(number = 1) {
  return {
    ticket_id: number.toString(16).padStart(32, "0"),
    ticket_hash: digest(secret(number)),
    expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
    generation: number,
  };
}
function session(number = 1) {
  return {
    url: `https://test-${number}.trycloudflare.com`,
    token: `agent-token-${number}-`.padEnd(64, "t"),
    host: "PC-test",
    os: "windows",
    session_id: number.toString(16).padStart(32, "0"),
    ticket_id: number.toString(16).padStart(32, "0"),
    delete_token: digest(`delete-session-${number}`),
  };
}
function request(method, key, body, headers = {}, path = "/session") {
  return mf.dispatchFetch(`https://worker.test${path}`, {
    method,
    headers: { authorization: `Bearer ${key}`, ...headers },
    ...(body === undefined ? {} : { body: typeof body === "string" ? body : JSON.stringify(body) }),
  });
}
const provision = record => request("POST", PROVISION_KEY, record, {}, "/ticket");
const readTicket = () => request("GET", PROVISION_KEY, undefined, {}, "/ticket");
const publish = (record, key = secret(parseInt(record.ticket_id, 16))) => request("POST", key, record);
const read = () => request("GET", READ_KEY);
const remove = record => request("DELETE", record.delete_token, undefined, { "x-relay-session-id": record.session_id });
async function prepare(number = 1) {
  const input = ticket(number);
  assert.equal((await provision(input)).status, 200);
  return input;
}

test("operator, reader, legacy writer and ticket roles stay separate", async () => {
  assert.equal((await read()).status, 404);
  assert.equal((await readTicket()).status, 404);
  for (const key of [READ_KEY, WRITE_KEY, secret(1), ""]) {
    assert.equal((await request("GET", key, undefined, {}, "/ticket")).status, 401);
    assert.equal((await request("POST", key, ticket(), {}, "/ticket")).status, 401);
  }
  for (const key of [WRITE_KEY, PROVISION_KEY, secret(1), ""]) assert.equal((await request("GET", key)).status, 401);
  await prepare();
  for (const key of [READ_KEY, WRITE_KEY, PROVISION_KEY, secret(2)]) assert.equal((await publish(session(), key)).status, 401);
  assert.equal((await (await readTicket()).json()).status, "pending");
  assert.equal((await publish(session())).status, 200);
  const response = await read();
  const body = await response.json();
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.deepEqual(Object.keys(body).sort(), ["url", "token", "host", "os", "session_id", "ticket_id", "published_at", "expires_at"].sort());
  assert.equal(body.token, session().token);
  assert.equal(body.ticket_id, session().ticket_id);
  assert.equal(Date.parse(body.expires_at) - Date.parse(body.published_at), 12 * 60 * 60 * 1000);
  assert.deepEqual(Object.keys(await (await readTicket()).json()).sort(), ["ticket_id", "generation", "expires_at", "status"].sort());
  const rows = await storage.exec("SELECT record, delete_hash, ticket_hash FROM current_session");
  assert.equal(rows[0].delete_hash, digest(session().delete_token));
  assert.equal(rows[0].ticket_hash, digest(secret(1)));
  assert.ok(!JSON.stringify(rows).includes(secret(1)));
  assert.ok(!JSON.stringify(rows).includes(session().delete_token));
  assert.equal((await request("DELETE", WRITE_KEY, undefined, { "x-relay-session-id": session().session_id })).status, 401);
  assert.equal((await remove({ ...session(), delete_token: secret(99) })).status, 404);
  assert.equal((await remove(session())).status, 200);
  assert.equal((await read()).status, 404);
});

test("ticket provisioning is monotonic, exact-idempotent and never rearms a claim", async () => {
  const initial = await prepare(10);
  assert.deepEqual(await (await provision(initial)).json(), await (await readTicket()).json());
  for (const patch of [{ generation: 9 }, { ticket_id: ticket(11).ticket_id }, { ticket_hash: ticket(11).ticket_hash }, { expires_at: new Date(Date.parse(initial.expires_at) + 1).toISOString() }]) {
    assert.equal((await provision({ ...initial, ...patch })).status, 409);
  }
  assert.equal((await publish(session(10))).status, 200);
  assert.equal((await (await provision(initial)).json()).status, "claimed");
  for (const patch of [{ ticket_id: initial.ticket_id }, { ticket_hash: initial.ticket_hash }]) {
    assert.equal((await provision({ ...ticket(11), ...patch })).status, 409);
  }
  await remove(session(10));
  assert.equal((await (await provision(initial)).json()).status, "closed");
  assert.equal((await publish(session(10))).status, 409);
  assert.equal((await read()).status, 404);
  const next = await prepare(11);
  assert.equal((await provision(initial)).status, 409);
  assert.equal((await (await readTicket()).json()).ticket_id, next.ticket_id);
});

test("concurrent provisioning preserves the greatest generation and revokes losing tickets", async () => {
  for (let base = 1; base < 30; base += 3) {
    const lower = ticket(base);
    const higher = ticket(base + 1);
    const responses = await Promise.all([provision(lower), provision(higher)]);
    assert.ok([200, 409].includes(responses[0].status));
    assert.equal(responses[1].status, 200);
    assert.equal((await (await readTicket()).json()).generation, higher.generation);
    assert.equal((await publish(session(base))).status, 401);
    assert.equal((await publish(session(base + 1))).status, 200);
    assert.equal((await provision(lower)).status, 409);
  }
});

test("publication retries are canonical and cannot change or prolong the session", async () => {
  await prepare();
  const record = session();
  const first = await (await publish(record)).json();
  const reordered = Object.fromEntries(Object.entries({ ...record, url: `${record.url}/` }).reverse());
  assert.deepEqual(await (await publish(reordered)).json(), first);
  for (const patch of [
    { url: session(2).url }, { token: session(2).token }, { host: "another host" }, { os: "unix" },
    { session_id: session(2).session_id }, { delete_token: session(2).delete_token },
  ]) assert.equal((await publish({ ...record, ...patch })).status, 409);
  assert.equal((await (await read()).json()).published_at, first.published_at);
  assert.equal((await (await read()).json()).expires_at, first.expires_at);
  assert.equal((await remove(record)).status, 200);
  assert.equal((await publish(record)).status, 409);
  assert.equal((await read()).status, 404);
});

test("concurrent publications consume one ticket exactly once", async () => {
  for (let number = 1; number <= 15; number++) {
    await prepare(number);
    const candidate = session(number);
    const competitor = { ...candidate, url: `https://competitor-${number}.trycloudflare.com`, session_id: session(number + 100).session_id };
    const results = await Promise.all([publish(candidate), publish(competitor)]);
    assert.deepEqual(results.map(response => response.status).sort(), [200, 409]);
    const current = await (await read()).json();
    assert.equal(current.session_id, results[0].status === 200 ? candidate.session_id : competitor.session_id);
    const duplicateResults = await Promise.all(Array.from({ length: 5 }, () => publish(results[0].status === 200 ? candidate : competitor)));
    assert.ok(duplicateResults.every(response => response.status === 200));
  }
});

test("new preparation keeps current, revokes previous publisher and protects pending from old cleanup", async () => {
  await prepare(1);
  await publish(session(1));
  await prepare(2);
  assert.equal((await (await read()).json()).ticket_id, session(1).ticket_id);
  assert.equal((await publish(session(1))).status, 401);
  assert.equal((await provision({ ...ticket(3), ticket_hash: ticket(1).ticket_hash })).status, 409);
  assert.equal((await provision({ ...ticket(3), ticket_id: ticket(1).ticket_id })).status, 409);
  assert.equal((await remove(session(1))).status, 200);
  assert.equal((await (await readTicket()).json()).status, "pending");
  assert.equal((await publish(session(2))).status, 200);
  assert.equal((await remove(session(1))).status, 404);
  assert.equal((await (await read()).json()).ticket_id, session(2).ticket_id);
});

test("old concurrent cleanup cannot erase the next session", async () => {
  for (let number = 1; number < 20; number += 2) {
    await prepare(number);
    await publish(session(number));
    await prepare(number + 1);
    const results = await Promise.all([remove(session(number)), publish(session(number + 1))]);
    assert.equal(results[1].status, 200);
    assert.equal((await (await read()).json()).session_id, session(number + 1).session_id);
    assert.equal((await remove(session(number))).status, 404);
    assert.equal((await (await readTicket()).json()).status, "claimed");
  }
});

test("pending expiration cannot revive tickets or erase the monotonic generation floor", async () => {
  const initial = await prepare(1);
  await storage.exec("UPDATE latest_ticket SET expires_ms = ?", Date.now() - 1);
  assert.equal((await publish(session(1))).status, 409);
  assert.equal((await (await readTicket()).json()).status, "expired");
  assert.equal((await (await provision(initial)).json()).status, "expired");
  assert.equal((await read()).status, 404);
  await mf.unsafeEvictDurableObject(OPTIONS.name, "SessionMailbox", SLOT);
  assert.equal((await (await readTicket()).json()).status, "expired");
  assert.equal((await provision({ ...initial, ticket_hash: ticket(2).ticket_hash })).status, 409);
  await prepare(2);
  assert.equal((await publish(session(1))).status, 401);
  assert.equal((await publish(session(2))).status, 200);
});

test("ticket activation expiry does not shorten an already claimed session", async () => {
  await prepare();
  await publish(session());
  const initial = await (await read()).json();
  await storage.exec("UPDATE latest_ticket SET expires_ms = ?", Date.now() - 1);
  assert.equal((await (await readTicket()).json()).status, "claimed");
  assert.deepEqual(await (await read()).json(), initial);
  assert.equal((await publish(session())).status, 200);
  await storage.exec("UPDATE current_session SET expires_ms = ?", Date.now() - 1);
  assert.equal((await read()).status, 404);
  assert.equal((await (await readTicket()).json()).status, "closed");
  assert.equal((await publish(session())).status, 409);
  assert.deepEqual(await storage.exec("SELECT * FROM current_session"), []);
  assert.equal((await storage.exec("SELECT generation FROM latest_ticket"))[0].generation, 1);
});

test("eviction preserves the current claim, deletion capability and tombstone", async () => {
  const initial = await prepare();
  await publish(session());
  await mf.unsafeEvictDurableObject(OPTIONS.name, "SessionMailbox", SLOT);
  assert.equal((await (await read()).json()).ticket_id, session().ticket_id);
  assert.equal((await (await provision(initial)).json()).status, "claimed");
  assert.equal((await remove(session())).status, 200);
  await mf.unsafeEvictDurableObject(OPTIONS.name, "SessionMailbox", SLOT);
  assert.equal((await (await provision(initial)).json()).status, "closed");
  assert.equal((await publish(session())).status, 409);
});

test("v1 stored sessions and publication bodies never downgrade the protocol", async () => {
  const legacy = session();
  delete legacy.ticket_id;
  assert.equal((await request("POST", WRITE_KEY, legacy)).status, 401);
  assert.equal((await request("POST", secret(1), legacy)).status, 400);
  await storage.exec("ALTER TABLE current_session DROP COLUMN ticket_hash");
  await storage.exec("INSERT INTO current_session (slot, record, delete_hash, expires_ms) VALUES (1, ?, ?, ?)", JSON.stringify(legacy), digest(legacy.delete_token), Date.now() + 100_000);
  await mf.unsafeEvictDurableObject(OPTIONS.name, "SessionMailbox", SLOT);
  assert.equal((await read()).status, 404);
  assert.deepEqual(await storage.exec("SELECT * FROM current_session"), []);
  assert.ok((await storage.exec("PRAGMA table_info(current_session)")).some(column => column.name === "ticket_hash"));
});

test("only literal HTTPS quick-tunnel origins are accepted", async () => {
  await prepare();
  for (const url of [
    "http://test.trycloudflare.com", "https://127.0.0.1", "http://localhost:47600/admin#",
    "https://trycloudflare.com", "https://a.b.trycloudflare.com", "https://a.trycloudflare.com.evil.test",
    "https://a.trycloudflare.com:443", "https://a.trycloudflare.com:8443", "https://!@a.trycloudflare.com",
    "https://a.trycloudflare.com/admin", "https://a.trycloudflare.com/../", "https://a.trycloudflare.com?x=1",
    "https://a.trycloudflare.com#", "https://a.trycloudflare.com/\\evil.test", " https://a.trycloudflare.com",
    "https://a.trycloudflare.com\n", "https://-a.trycloudflare.com", "https://a-.trycloudflare.com",
    `https://${"a".repeat(64)}.trycloudflare.com`,
  ]) assert.equal((await publish({ ...session(), url })).status, 400, url);
  assert.equal((await publish({ ...session(), url: "https://valid-tunnel.trycloudflare.com/" })).status, 200);
  assert.equal((await (await read()).json()).url, "https://valid-tunnel.trycloudflare.com");
});

test("strict session JSON validation rejects unknown, missing and oversized fields", async () => {
  for (const body of ["null", "[]", "1", "true", '"text"', "{", "{}"]) assert.equal((await request("POST", secret(1), body)).status, 400, body);
  for (const patch of [
    { extra: "secret-marker" }, { host: null }, { host: "x".repeat(129) }, { os: "x".repeat(33) },
    { host: "line\nbreak" }, { host: "control\u0085" }, { token: "t".repeat(31) },
    { token: "t".repeat(257) }, { token: "a ".repeat(32) }, { session_id: "F".repeat(32) },
    { delete_token: "f".repeat(63) }, { session_id: null }, { ticket_id: undefined }, { ticket_id: "F".repeat(32) },
  ]) {
    const response = await request("POST", secret(1), { ...session(), ...patch });
    assert.equal(response.status, 400);
    assert.deepEqual(await response.json(), { error: "invalid session" });
  }
});

test("ticket schemas reject unsafe generations, ambiguous dates and unbounded lifetime", async () => {
  for (const body of ["null", "[]", "1", "true", '"text"', "{", "{}"]) assert.equal((await provision(body)).status, 400, body);
  for (const patch of [
    { extra: true }, { ticket_id: "F".repeat(32) }, { ticket_hash: "f".repeat(63) }, { ticket_hash: "F".repeat(64) },
    { generation: 0 }, { generation: -1 }, { generation: 1.5 }, { generation: Number.MAX_SAFE_INTEGER + 1 }, { generation: "1" },
    { expires_at: new Date(Date.now() - 1).toISOString() }, { expires_at: new Date(Date.now() + 8 * 86400_000).toISOString() },
    { expires_at: "2026-02-30T00:00:00.000Z" }, { expires_at: "2026-09-10T00:00:00+00:00" },
  ]) assert.equal((await provision({ ...ticket(), ...patch })).status, 400, JSON.stringify(patch));
  assert.equal((await readTicket()).status, 404);
});

test("request size limit applies to streamed and declared bodies for both endpoints", async () => {
  for (const path of ["/session", "/ticket"]) {
    const key = path === "/session" ? secret(1) : PROVISION_KEY;
    const chunks = [" ".repeat(2500), " ".repeat(2500)];
    const body = new ReadableStream({ pull(controller) {
      const chunk = chunks.shift();
      if (chunk === undefined) controller.close();
      else controller.enqueue(new TextEncoder().encode(chunk));
    } });
    const response = await mf.dispatchFetch(`https://worker.test${path}`, {
      method: "POST", headers: { authorization: `Bearer ${key}` }, body, duplex: "half",
    });
    assert.equal(response.status, 413);
    assert.equal((await request("POST", key, " ".repeat(5000), {}, path)).status, 413);
  }
});

test("missing, invalid, identical or legacy-only operator configuration fails closed", async () => {
  try {
    for (const bindings of [
      { READ_KEY }, { PROVISION_KEY }, { READ_KEY, WRITE_KEY }, { READ_KEY, PROVISION_KEY: "" },
      { READ_KEY, PROVISION_KEY: "a".repeat(63) }, { READ_KEY: PROVISION_KEY, PROVISION_KEY },
    ]) {
      await mf.setOptions(convertV4MiniflareOptions({ ...OPTIONS, bindings }));
      for (const path of ["/session", "/ticket"]) for (const method of ["GET", "POST", "DELETE"]) {
        const response = await request(method, READ_KEY, method === "POST" ? session() : undefined, {}, path);
        assert.equal(response.status, 503);
        assert.deepEqual(await response.json(), { error: "service unavailable" });
      }
    }
  } finally {
    await mf.setOptions(convertV4MiniflareOptions(OPTIONS));
    storage = await mf.unsafeGetDurableObjectStorage(OPTIONS.name, "SessionMailbox", SLOT);
  }
});

test("persistent ticket opens multiple sessions without renewal and rejects active takeover and replay", async () => {
 const credential={...ticket(),expires_at:null};assert.equal((await provision(credential)).status,200);
 const one=session();assert.equal((await publish(one)).status,200);const first=await (await read()).json();assert.equal(first.sequence,1);
 assert.equal((await publish(one)).status,200);assert.deepEqual(await (await read()).json(),first);
 const two={...session(2),ticket_id:one.ticket_id};assert.equal((await publish(two)).status,409);
 assert.equal((await remove(one)).status,200);assert.equal((await (await readTicket()).json()).expires_at,null);
 assert.equal((await publish(one)).status,409);assert.equal((await publish(two)).status,200);
 const second=await (await read()).json();assert.equal(second.sequence,2);
 assert.equal((await remove(one)).status,404);assert.deepEqual(await (await read()).json(),second);
 await storage.exec("UPDATE current_session SET expires_ms = ?",Date.now()-1);
 assert.equal((await read()).status,404);assert.equal((await publish(two)).status,409);
 const three={...session(3),ticket_id:one.ticket_id};assert.equal((await publish(three)).status,200);
 assert.equal((await (await read()).json()).sequence,3);
});
test("simultaneous holders of a persistent ticket cannot replace an active session", async () => {
 await provision({...ticket(),expires_at:null});const one=session(),two={...session(2),ticket_id:one.ticket_id};
 const results=await Promise.all([publish(one),publish(two)]);assert.deepEqual(results.map(r=>r.status).sort(),[200,409]);
});
test("operator can promote v2 ticket in place without altering its running session", async () => {
 const initial=await prepare();const one=session();await publish(one);const before=await (await read()).json();
 const permanent={...initial,expires_at:null};assert.equal((await provision(permanent)).status,200);
 assert.deepEqual(await (await read()).json(),before);assert.equal((await provision(permanent)).status,200);
 assert.equal((await provision(initial)).status,409);
 await remove(one);assert.equal((await publish(one)).status,409);
 assert.equal((await publish({...session(2),ticket_id:one.ticket_id})).status,200);
});
test("persistent state and replay prevention survive eviction and explicit credential rotation", async () => {
 await provision({...ticket(),expires_at:null});const one=session();await publish(one);await remove(one);
 await mf.unsafeEvictDurableObject(OPTIONS.name,"SessionMailbox",SLOT);
 assert.equal((await publish(one)).status,409);
 const two={...session(2),ticket_id:one.ticket_id};assert.equal((await publish(two)).status,200);await remove(two);
 await provision({...ticket(2),expires_at:null});assert.equal((await publish({...session(3),ticket_id:one.ticket_id})).status,401);
 assert.equal((await publish(session(4),secret(1))).status,401);
 const next={...session(4),ticket_id:ticket(2).ticket_id};assert.equal((await publish(next)).status,200);
 assert.equal((await (await read()).json()).sequence,3);
});
