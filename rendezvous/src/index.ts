import { DurableObject } from "cloudflare:workers";
import { createHash, timingSafeEqual } from "node:crypto";

interface Env extends Cloudflare.Env {
  READ_KEY: string;
  PROVISION_KEY: string;
}

type PublishedSession = {
  url: string;
  token: string;
  host: string;
  os: string;
  session_id: string;
  ticket_id: string;
  published_at: string;
  expires_at: string;
  sequence?: number;
};
type SessionInput = Omit<PublishedSession, "published_at" | "expires_at" | "sequence">;
type StoredSession = {
  record: string;
  delete_hash: string;
  ticket_hash: string | null;
  expires_ms: number;
};

type TicketInput = {
  ticket_id: string;
  ticket_hash: string;
  expires_at: string | null;
  generation: number;
};
type TicketStatus = "pending" | "claimed" | "closed" | "expired";
type StoredTicket = TicketInput & { status: TicketStatus; expires_ms: number; persistent: number };
type PublicTicket = Omit<TicketInput, "ticket_hash"> & { status: TicketStatus };
type ProvisionResult = { status: 200; ticket: PublicTicket } | { status: 400 | 409 };
type PublishResult = { status: 200; record: PublishedSession } | { status: 401 | 409 };

const TICKET_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const TTL_MS = 12 * 60 * 60 * 1000;
const MAX_BODY_BYTES = 4096;
const SESSION_ID = /^[a-f0-9]{32}$/;
const DELETE_TOKEN = /^[a-f0-9]{64}$/;
const TOKEN = /^[\x21-\x7e]{32,256}$/;
const ENCODER = new TextEncoder();

function json(body: unknown, status = 200): Response {
  return Response.json(body, {
    status,
    headers: { "cache-control": "no-store", "x-content-type-options": "nosniff" },
  });
}

function secretEq(a: string, b: string): boolean {
  const left = ENCODER.encode(a);
  const right = ENCODER.encode(b);
  return left.byteLength > 0 && left.byteLength === right.byteLength && timingSafeEqual(left, right);
}

function bearer(req: Request): string {
  return /^Bearer ([\x21-\x7e]{1,256})$/i.exec(req.headers.get("authorization") ?? "")?.[1] ?? "";
}

function digest(value: string): string {
  return createHash("sha256").update(value).digest("hex");
}

function tunnelOrigin(value: unknown): string | undefined {
  // Check raw spelling too: URL normalizes :443, dot segments and backslashes.
  if (typeof value !== "string" ||
      !/^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com\/?$/.test(value)) return undefined;
  return new URL(value).origin;
}

function metadata(value: unknown, max: number): value is string | undefined {
  return value === undefined || (typeof value === "string" && value.length <= max && !/[\x00-\x1f\x7f-\x9f]/.test(value));
}

class BodyError extends Error {
  status: number;
  constructor(message: string, status: number) {
    super(message);
    this.status = status;
  }
}

async function readBody(req: Request): Promise<unknown> {
  const length = req.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > MAX_BODY_BYTES)) {
    throw new BodyError("body too large", 413);
  }
  if (!req.body) throw new BodyError("invalid JSON body", 400);
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_BODY_BYTES) {
        await reader.cancel();
        throw new BodyError("body too large", 413);
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(bytes));
  } catch {
    throw new BodyError("invalid JSON body", 400);
  }
}

function parseSession(body: unknown): { session: SessionInput; deleteHash: string } | undefined {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return undefined;
  const input = body as Record<string, unknown>;
  if (Object.keys(input).some(key => !["url", "token", "host", "os", "session_id", "delete_token", "ticket_id"].includes(key))) return undefined;
  const url = tunnelOrigin(input.url);
  if (!url || typeof input.token !== "string" || !TOKEN.test(input.token) ||
      typeof input.session_id !== "string" || !SESSION_ID.test(input.session_id) ||
      typeof input.ticket_id !== "string" || !SESSION_ID.test(input.ticket_id) ||
      typeof input.delete_token !== "string" || !DELETE_TOKEN.test(input.delete_token) ||
      !metadata(input.host, 128) || !metadata(input.os, 32)) return undefined;
  return {
    session: { url, token: input.token, host: input.host ?? "", os: input.os ?? "", session_id: input.session_id, ticket_id: input.ticket_id },
    deleteHash: digest(input.delete_token),
  };
}

function parseTicket(body: unknown): TicketInput | undefined {
  if (body === null || typeof body !== "object" || Array.isArray(body)) return undefined;
  const input = body as Record<string, unknown>;
  if (Object.keys(input).some(key => !["ticket_id", "ticket_hash", "expires_at", "generation"].includes(key)) ||
      typeof input.ticket_id !== "string" || !SESSION_ID.test(input.ticket_id) ||
      typeof input.ticket_hash !== "string" || !DELETE_TOKEN.test(input.ticket_hash) ||
      (input.expires_at !== null && (typeof input.expires_at !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(input.expires_at) ||
      !Number.isFinite(Date.parse(input.expires_at)) || new Date(input.expires_at).toISOString() !== input.expires_at)) ||
      typeof input.generation !== "number" || !Number.isSafeInteger(input.generation) || input.generation <= 0) return undefined;
  return { ticket_id: input.ticket_id, ticket_hash: input.ticket_hash, expires_at: input.expires_at, generation: input.generation };
}

function publicTicket(ticket: StoredTicket): PublicTicket {
  return { ticket_id: ticket.ticket_id, generation: ticket.generation, expires_at: ticket.expires_at, status: ticket.status };
}

function publicationDigest(session: SessionInput, deleteHash: string): string {
  // Fixed key ordering and normalized origins make transport retries idempotent.
  return digest(JSON.stringify({
    url: session.url, token: session.token, host: session.host, os: session.os,
    session_id: session.session_id, ticket_id: session.ticket_id, delete_hash: deleteHash,
  }));
}

// One operator mailbox is the coordination atom. All decisions and mutations are
// synchronous SQLite transactions; no request can publish between check/consume.
export class SessionMailbox extends DurableObject<Env> {
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env);
    this.ctx.storage.sql.exec(`CREATE TABLE IF NOT EXISTS current_session (
      slot INTEGER PRIMARY KEY CHECK (slot = 1),
      record TEXT NOT NULL,
      delete_hash TEXT NOT NULL,
      expires_ms INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS latest_ticket (
      slot INTEGER PRIMARY KEY CHECK (slot = 1),
      ticket_id TEXT NOT NULL,
      ticket_hash TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      expires_ms INTEGER NOT NULL,
      generation INTEGER NOT NULL,
      status TEXT NOT NULL CHECK (status IN ('pending', 'claimed', 'closed', 'expired'))
    );
    CREATE TABLE IF NOT EXISTS seen_sessions (
      ticket_id TEXT NOT NULL, session_id TEXT NOT NULL,
      PRIMARY KEY (ticket_id, session_id)
    );
    CREATE TABLE IF NOT EXISTS session_counter (slot INTEGER PRIMARY KEY CHECK (slot = 1), value INTEGER NOT NULL);
    INSERT OR IGNORE INTO session_counter (slot, value) VALUES (1, 0)`);
    const ticketColumns = this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(latest_ticket)").toArray();
    if (!ticketColumns.some(column => column.name === "persistent")) {
      this.ctx.storage.sql.exec("ALTER TABLE latest_ticket ADD COLUMN persistent INTEGER NOT NULL DEFAULT 0");
    }
    const columns = this.ctx.storage.sql.exec<{ name: string }>("PRAGMA table_info(current_session)").toArray();
    if (!columns.some(column => column.name === "ticket_hash")) {
      this.ctx.storage.sql.exec("ALTER TABLE current_session ADD COLUMN ticket_hash TEXT");
    }
  }

  async provision(input: TicketInput): Promise<ProvisionResult> {
    const result = this.ctx.storage.transactionSync<ProvisionResult>(() => {
      const now = Date.now();
      const current = this.current(now);
      const previous = this.ticket(now);
      if (previous && input.generation <= previous.generation) {
        const sameCredential = input.generation === previous.generation && input.ticket_id === previous.ticket_id &&
          secretEq(input.ticket_hash, previous.ticket_hash);
        // Explicit operator-only migration preserves both the credential and an
        // already running v2 session. A retry cannot revert persistence.
        if (sameCredential && input.expires_at === null && !previous.persistent) {
          const status = current && (JSON.parse(current.record) as PublishedSession).ticket_id === input.ticket_id ? "claimed" : "pending";
          this.ctx.storage.sql.exec("UPDATE latest_ticket SET persistent = 1, expires_at = '', expires_ms = 0, status = ? WHERE slot = 1", status);
          return { status: 200, ticket: { ...publicTicket(previous), expires_at: null, status } };
        }
        return sameCredential && input.expires_at === previous.expires_at ? { status: 200, ticket: publicTicket(previous) } : { status: 409 };
      }
      const currentId = current ? (JSON.parse(current.record) as PublishedSession).ticket_id : undefined;
      if (previous && (input.ticket_id === previous.ticket_id || secretEq(input.ticket_hash, previous.ticket_hash)) ||
          current && (input.ticket_id === currentId || current.ticket_hash !== null && secretEq(input.ticket_hash, current.ticket_hash))) {
        return { status: 409 };
      }
      const persistent = input.expires_at === null;
      const expires = persistent ? 0 : Date.parse(input.expires_at!);
      if (!persistent && (expires <= now || expires - now > TICKET_TTL_MS)) return { status: 400 };
      this.ctx.storage.sql.exec(
        `INSERT OR REPLACE INTO latest_ticket (slot, ticket_id, ticket_hash, expires_at, expires_ms, generation, status, persistent)
         VALUES (1, ?, ?, ?, ?, ?, 'pending', ?)`,
        input.ticket_id, input.ticket_hash, input.expires_at ?? "", expires, input.generation, persistent ? 1 : 0,
      );
      return { status: 200, ticket: { ticket_id: input.ticket_id, generation: input.generation, expires_at: input.expires_at, status: "pending" } };
    });
    await this.refreshAlarm();
    return result;
  }

  readTicket(): PublicTicket | null {
    this.current();
    const ticket = this.ticket();
    return ticket ? publicTicket(ticket) : null;
  }

  async publish(session: SessionInput, deleteHash: string, ticketHash: string): Promise<PublishResult> {
    const result = this.ctx.storage.transactionSync<PublishResult>(() => {
      const now = Date.now();
      const row = this.current(now);
      const ticket = this.ticket(now);
      if (!ticket || ticket.ticket_id !== session.ticket_id || !secretEq(ticket.ticket_hash, ticketHash)) return { status: 401 };
      if (ticket.status === "claimed" && row) {
        const record = JSON.parse(row.record) as PublishedSession;
        if (record.ticket_id === ticket.ticket_id &&
            secretEq(publicationDigest(record, row.delete_hash), publicationDigest(session, deleteHash))) {
          return { status: 200, record };
        }
      }
      let sequence: number | undefined;
      if (ticket.persistent) {
        // A reusable credential may open successive sessions, never replace an
        // active one. The session's own deletion capability is still required.
        if (row || this.ctx.storage.sql.exec("SELECT 1 FROM seen_sessions WHERE ticket_id = ? AND session_id = ?", session.ticket_id, session.session_id).toArray().length) return { status: 409 };
        sequence = this.ctx.storage.sql.exec<{ value: number }>("UPDATE session_counter SET value = value + 1 WHERE slot = 1 AND value < 9007199254740991 RETURNING value").toArray()[0]?.value;
        if (sequence === undefined) return { status: 409 };
      } else if (ticket.status !== "pending") return { status: 409 };
      const expires = now + TTL_MS;
      const record = { ...session, published_at: new Date(now).toISOString(), expires_at: new Date(expires).toISOString(), ...(sequence === undefined ? {} : { sequence }) };
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO seen_sessions (ticket_id, session_id) VALUES (?, ?)", session.ticket_id, session.session_id);
      this.ctx.storage.sql.exec(
        "INSERT OR REPLACE INTO current_session (slot, record, delete_hash, ticket_hash, expires_ms) VALUES (1, ?, ?, ?, ?)",
        JSON.stringify(record), deleteHash, ticketHash, expires,
      );
      this.ctx.storage.sql.exec("UPDATE latest_ticket SET status = 'claimed' WHERE slot = 1");
      return { status: 200, record };
    });
    await this.refreshAlarm();
    return result;
  }

  read(): PublishedSession | null {
    const row = this.current();
    return row ? JSON.parse(row.record) as PublishedSession : null;
  }

  async remove(sessionId: string, deleteHash: string): Promise<boolean> {
    const removed = this.ctx.storage.transactionSync(() => {
      const row = this.current();
      if (!row) return false;
      const record = JSON.parse(row.record) as PublishedSession;
      if (record.session_id !== sessionId || !secretEq(row.delete_hash, deleteHash)) return false;
      this.ctx.storage.sql.exec("DELETE FROM current_session WHERE slot = 1");
      this.ctx.storage.sql.exec("UPDATE latest_ticket SET status = CASE WHEN persistent = 1 THEN 'pending' ELSE 'closed' END WHERE slot = 1 AND ticket_id = ? AND status = 'claimed'", record.ticket_id);
      return true;
    });
    await this.refreshAlarm();
    return removed;
  }

  async alarm(): Promise<void> {
    await this.refreshAlarm();
  }

  private async refreshAlarm(): Promise<void> {
    const now = Date.now();
    const row = this.current(now);
    const ticket = this.ticket(now);
    const deadlines = [row?.expires_ms, ticket?.status === "pending" && !ticket.persistent ? ticket.expires_ms : undefined]
      .filter((value): value is number => value !== undefined);
    // A stale alarm cannot remove a newer session or forget the generation floor.
    if (deadlines.length) await this.ctx.storage.setAlarm(Math.min(...deadlines));
    else await this.ctx.storage.deleteAlarm();
  }

  private ticket(now = Date.now()): StoredTicket | undefined {
    const row = this.ctx.storage.sql.exec<StoredTicket>("SELECT * FROM latest_ticket WHERE slot = 1").toArray()[0];
    if (row?.persistent) row.expires_at = null;
    if (row?.status === "pending" && !row.persistent && row.expires_ms <= now) {
      this.ctx.storage.sql.exec("UPDATE latest_ticket SET status = 'expired' WHERE slot = 1");
      row.status = "expired";
    }
    return row;
  }

  private current(now = Date.now()): StoredSession | undefined {
    const row = this.ctx.storage.sql.exec<StoredSession>(
      "SELECT record, delete_hash, ticket_hash, expires_ms FROM current_session WHERE slot = 1",
    ).toArray()[0];
    if (!row) return undefined;
    const record = JSON.parse(row.record) as Partial<PublishedSession>;
    if (typeof record.ticket_id === "string" && typeof record.session_id === "string") {
      this.ctx.storage.sql.exec("INSERT OR IGNORE INTO seen_sessions (ticket_id, session_id) VALUES (?, ?)", record.ticket_id, record.session_id);
    }
    // Previously published v1 sessions have no ticket and are never trusted by v2.
    if (row.expires_ms <= now || typeof record.ticket_id !== "string" || !SESSION_ID.test(record.ticket_id)) {
      this.ctx.storage.sql.exec("DELETE FROM current_session WHERE slot = 1");
      if (typeof record.ticket_id === "string") {
        this.ctx.storage.sql.exec("UPDATE latest_ticket SET status = CASE WHEN persistent = 1 THEN 'pending' ELSE 'closed' END WHERE slot = 1 AND ticket_id = ? AND status = 'claimed'", record.ticket_id);
      }
      return undefined;
    }
    return row;
  }
}

export default {
  async fetch(req: Request, env: Env): Promise<Response> {
    try {
      const { pathname } = new URL(req.url);
      if (pathname === "/" && req.method === "GET") return json({ ok: true, service: "relay-rendezvous", protocol: 3 });
      if (pathname !== "/session" && pathname !== "/ticket") return json({ error: "not found" }, 404);
      if (typeof env.READ_KEY !== "string" || !TOKEN.test(env.READ_KEY) ||
          typeof env.PROVISION_KEY !== "string" || !DELETE_TOKEN.test(env.PROVISION_KEY) || secretEq(env.READ_KEY, env.PROVISION_KEY)) {
        return json({ error: "service unavailable" }, 503);
      }
      const supplied = bearer(req);
      const mailbox = env.MAILBOX.getByName("operator-session");
      if (pathname === "/ticket") {
        if (!secretEq(supplied, env.PROVISION_KEY)) return json({ error: "unauthorized" }, 401);
        if (req.method === "GET") {
          const ticket = await mailbox.readTicket();
          return ticket ? json(ticket) : json({ error: "no prepared ticket" }, 404);
        }
        if (req.method !== "POST") return json({ error: "method not allowed" }, 405);
        const input = parseTicket(await readBody(req));
        if (!input) return json({ error: "invalid ticket" }, 400);
        const result = await mailbox.provision(input);
        if (result.status !== 200) return json({ error: result.status === 400 ? "invalid ticket expiration" : "ticket generation conflict" }, result.status);
        return json(result.ticket);
      }
      switch (req.method) {
        case "POST": {
          // A publisher holds a package credential, never an operator read/provision key.
          if (!DELETE_TOKEN.test(supplied)) return json({ error: "unauthorized" }, 401);
          const parsed = parseSession(await readBody(req));
          if (!parsed) return json({ error: "invalid session" }, 400);
          const result = await mailbox.publish(parsed.session, parsed.deleteHash, digest(supplied));
          if (result.status !== 200) return json({ error: result.status === 401 ? "unauthorized" : "active session, replay, or expired ticket" }, result.status);
          const record = result.record;
          return json({ ok: true, ticket_id: record.ticket_id, session_id: record.session_id, published_at: record.published_at, expires_at: record.expires_at });
        }
        case "GET": {
          if (!secretEq(supplied, env.READ_KEY)) return json({ error: "unauthorized" }, 401);
          const record = await mailbox.read();
          return record ? json(record) : json({ error: "no active session" }, 404);
        }
        case "DELETE": {
          const id = req.headers.get("x-relay-session-id") ?? "";
          if (!DELETE_TOKEN.test(supplied) || !SESSION_ID.test(id)) return json({ error: "unauthorized" }, 401);
          const deleted = await mailbox.remove(id, digest(supplied));
          return deleted ? json({ ok: true }) : json({ error: "session not found or unauthorized" }, 404);
        }
        default:
          return json({ error: "method not allowed" }, 405);
      }
    } catch (error) {
      if (error instanceof BodyError) return json({ error: error.message }, error.status);
      // Never reflect storage exceptions, request bodies, URLs, or credentials.
      return json({ error: "service unavailable" }, 503);
    }
  },
} satisfies ExportedHandler<Env>;
