import { createHash } from "node:crypto";
import { z } from "zod";

export const STREAM_LIMIT = 1 << 20;
// JSON may encode each captured byte as six ASCII bytes.
export const EXEC_RESPONSE_LIMIT = 12 * STREAM_LIMIT + 4096;
export const SESSION_RESPONSE_LIMIT = 4096;
export const HEALTH_RESPONSE_LIMIT = 4096;
export const REQUEST_LIMIT = 64 << 10;
export const SESSION_LIFETIME_MS = 12 * 60 * 60 * 1000;
export const CLIENT_MARGIN_MS = 15_000;
export class RelayError extends Error {}

const label = (max: number) => z.string().max(max).regex(/^[^\u0000-\u001f\u007f-\u009f]*$/);
export const tokenSchema = z.string().min(32).max(256).regex(/^[\x21-\x7e]+$/);
const timestamp = z.string().datetime({ offset: true });
export const sessionSchema = z.object({
  url: z.string().max(253), token: tokenSchema, host: label(128), os: label(32),
  ticket_id: z.string().regex(/^[a-f0-9]{32}$/),
  sequence: z.number().int().safe().positive().optional(),
  session_id: z.string().regex(/^[a-f0-9]{32}$/), published_at: timestamp, expires_at: timestamp,
}).strict();
export type Session = z.infer<typeof sessionSchema>;
export type Target = { url: string; token: string } & Partial<Omit<Session, "url" | "token">>;
export const healthSchema = z.object({
  status: z.literal("ok"), agent: z.literal("relay-agent"), version: label(64),
  os: label(32), arch: label(32), time: timestamp, pid: z.number().int().positive(),
  default_timeout_seconds: z.number().int().min(1).max(3600),
});
export const execSchema = z.object({
  exit_code: z.number().int(), stdout: z.string().max(STREAM_LIMIT), stderr: z.string().max(STREAM_LIMIT),
  timed_out: z.boolean(), truncated: z.boolean(), duration_ms: z.number().finite().nonnegative(),
}).strict();

// Check raw spelling too: URL normalizes whitespace, ports and dot segments.
export function tunnelOrigin(raw: string): string {
  if (!/^https:\/\/[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.trycloudflare\.com\/?$/.test(raw)) {
    throw new RelayError("session URL must be a plain HTTPS trycloudflare.com origin");
  }
  return new URL(raw).origin;
}

export function configuredOrigin(raw: string, allowLoopback = false): string {
  if (raw !== raw.trim() || /[\\\s?#]/.test(raw)) throw new RelayError("configured URL must be a plain origin");
  let url: URL;
  try { url = new URL(raw); } catch { throw new RelayError("invalid configured URL"); }
  if (url.username || url.password || url.pathname !== "/" || url.search || url.hash) {
    throw new RelayError("configured URL must not contain credentials, a path, query or fragment");
  }
  const loopback = url.hostname === "127.0.0.1" || url.hostname === "[::1]";
  if (url.protocol !== "https:" && !(allowLoopback && loopback && url.protocol === "http:")) {
    throw new RelayError("HTTPS is required (static tests may explicitly use HTTP loopback)");
  }
  return url.origin;
}

export function parseSession(value: unknown, now = Date.now()): Session {
  const parsed = sessionSchema.safeParse(value);
  if (!parsed.success) throw new RelayError("rendezvous returned an invalid session; update the Worker and launcher together");
  const session = parsed.data;
  session.url = tunnelOrigin(session.url);
  const published = Date.parse(session.published_at);
  const expires = Date.parse(session.expires_at);
  if (expires <= now || published > now + 60_000 || expires <= published || expires - published > SESSION_LIFETIME_MS) {
    throw new RelayError("rendezvous session is expired or has invalid validity dates");
  }
  return session;
}

export function targetIdentity(target: Target): string {
  const fields: unknown[] = [target.url, target.token, target.ticket_id, target.session_id, target.published_at, target.expires_at];
  // Keep the fingerprint of a currently running v2 session unchanged.
  if (target.sequence !== undefined) fields.push(target.sequence);
  return createHash("sha256").update(JSON.stringify(fields)).digest("hex");
}

export function httpBudgetMs(seconds: number, override?: number): number {
  if (!Number.isInteger(seconds) || seconds < 1 || seconds > 3600) throw new RelayError("timeout must be an integer between 1 and 3600 seconds");
  if (override !== undefined && (!Number.isSafeInteger(override) || override <= 0 || override > 3_615_000)) {
    throw new RelayError("HTTP timeout override must be between 1 and 3615000 milliseconds");
  }
  const minimum = seconds * 1000 + CLIENT_MARGIN_MS;
  if (override !== undefined && override < minimum) throw new RelayError("HTTP timeout override is shorter than the command timeout plus its safety margin");
  return override ?? minimum;
}

export async function readJsonLimited(response: Response, limit: number): Promise<unknown> {
  const length = response.headers.get("content-length");
  if (length !== null && (!/^\d+$/.test(length) || Number(length) > limit)) {
    await response.body?.cancel();
    throw new RelayError("response exceeds the permitted size");
  }
  if (!response.body) throw new RelayError("empty JSON response");
  const reader = response.body.getReader();
  const decoder = new TextDecoder("utf-8", { fatal: true });
  // A fixed buffer also bounds bookkeeping for a stream of tiny chunks.
  const bytes = new Uint8Array(limit);
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength > limit - size) throw new RelayError("response exceeds the permitted size");
      bytes.set(value, size);
      size += value.byteLength;
    }
    const text = decoder.decode(bytes.subarray(0, size));
    try { return JSON.parse(text) as unknown; }
    catch { throw new RelayError("invalid JSON response"); }
  } catch (error) {
    await reader.cancel().catch(() => {});
    if (error instanceof RelayError) throw error;
    throw new RelayError("response could not be read as UTF-8 JSON");
  } finally { reader.releaseLock(); }
}
