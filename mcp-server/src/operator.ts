import { constants } from "node:fs";
import { homedir } from "node:os";
import { mkdir, lstat, open, readdir, rename, realpath, rm } from "node:fs/promises";
import { dirname, basename, isAbsolute, join, resolve, sep } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { z } from "zod";
import { configuredOrigin, readJsonLimited, RelayError, targetIdentity, type Session } from "./security.js";
const exec = promisify(execFile);
const hex = (length: number) => z.string().regex(new RegExp(`^[a-f0-9]{${length}}$`));
const ticketMetadataSchema = z.object({ ticket_id: hex(32), generation: z.number().int().safe().positive(), expires_at: z.string().datetime().nullable(), status: z.enum(["pending", "claimed", "closed", "expired"]) }).strict();
const schema = z.object({
  version: z.union([z.literal(2), z.literal(3)]), rendezvous_url: z.string(), provision_key: hex(64),
  package: z.object({ directory: z.string(), volume_uuid: z.string().regex(/^[a-fA-F0-9-]{8,64}$/).optional(), source_directory: z.string() }).strict(),
  expected_ticket_id: hex(32).optional(),
  ticket: z.object({ id: hex(32), secret: hex(64), expires_at: z.string().datetime().nullable(), generation: z.number().int().safe().nonnegative() }).strict().optional(),
  pinned_sequence: z.number().int().safe().positive().optional(),
  pinned_identity: hex(64).optional(), preparation: z.object({ phase: z.enum(["created", "registered"]) }).strict().optional(),
  mounted: z.boolean().optional(), mounted_identity: z.string().min(1).max(128).optional(), last_generation: z.number().int().safe().nonnegative().optional(),
}).strict();
export type OperatorState = z.infer<typeof schema>;
export type VolumeIdentity = { uuid: string; mountPoint: string; external: boolean; writable: boolean; incarnation: string };
export type OperatorOptions = {
  fetch?: typeof fetch; volumeProbe?: (directory: string) => Promise<VolumeIdentity | null>; now?: () => number;
  /** Crash injection for tests only. */
  afterPhase?: (phase: "intent" | "registered" | "archived" | "installed") => Promise<void>;
};
export const PACKAGE_FILES = ["start-relay.cmd", "start-relay.ps1", "relay-common.ps1", "relay-cleaner.ps1", "cleanup.cmd", "tests.ps1", "rendezvous.example.json", "README.txt", "relay-agent-windows-amd64.exe"] as const;
// Preserve already installed configurations without changing their credentials.
export function defaultOperatorStatePath(): string {
  return join(homedir(), ".config", "remote-support-relay", "operator.json");
}
const failure = (message: string) => new RelayError(message);
const isError = (error: unknown, code: string) => (error as NodeJS.ErrnoException)?.code === code;
async function exists(path: string): Promise<boolean> { try { await lstat(path); return true; } catch (error) { if (isError(error, "ENOENT")) return false; throw error; } }
async function noLinks(path: string): Promise<void> {
  if (!isAbsolute(path) || resolve(path) !== path) throw failure("operator paths must be absolute and canonical");
  for (let cursor = path;; cursor = dirname(cursor)) {
    try { if ((await lstat(cursor)).isSymbolicLink()) throw failure("symbolic links are not permitted in operator paths"); }
    catch (error) { if (!isError(error, "ENOENT")) throw error; }
    if (dirname(cursor) === cursor) return;
  }
}
async function privateDirectory(path: string, create = false): Promise<void> {
  await noLinks(path); if (create) await mkdir(path, { recursive: true, mode: 0o700 });
  const info = await lstat(path);
  if (!info.isDirectory() || info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0) throw failure("operator directory must be owned by this user with mode 0700");
}
async function boundedFile(path: string, limit: number, secret = false): Promise<Buffer> {
  await noLinks(path);
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    if (!info.isFile() || info.nlink > 1 || info.size > limit || (secret && (info.uid !== process.getuid?.() || (info.mode & 0o077) !== 0))) throw failure("invalid or insufficiently protected operator file");
    const bytes = Buffer.alloc(Math.min(info.size + 1, limit + 1)); let count = 0;
    while (count < bytes.length) { const result = await file.read(bytes, count, bytes.length - count, null); if (!result.bytesRead) break; count += result.bytesRead; }
    if (count > limit || count !== info.size) throw failure("operator file changed while being read");
    return bytes.subarray(0, count);
  } finally { await file.close(); }
}
async function atomicJson(path: string, value: unknown): Promise<void> {
  await noLinks(path);
  const temporary = join(dirname(path), `.${basename(path)}.${randomBytes(12).toString("hex")}.tmp`);
  const file = await open(temporary, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { await file.writeFile(JSON.stringify(value) + "\n"); await file.sync(); } finally { await file.close(); }
  try {
    await rename(temporary, path);
    const directory = await open(dirname(path), constants.O_RDONLY); try { await directory.sync(); } finally { await directory.close(); }
  } catch (error) { await rm(temporary, { force: true }); throw error; }
}
function parseState(value: unknown): OperatorState {
  const parsed = schema.safeParse(value); if (!parsed.success) throw failure("operator state is invalid; prepare the package from the operator workstation");
  const state = parsed.data; state.rendezvous_url = configuredOrigin(state.rendezvous_url);
  if (!isAbsolute(state.package.directory) || !isAbsolute(state.package.source_directory) ||
      (state.ticket && state.expected_ticket_id !== state.ticket.id) || (state.preparation && !state.ticket) ||
      (state.pinned_identity && !state.expected_ticket_id)) throw failure("operator state has inconsistent trust settings");
  return state;
}
export async function readOperatorState(path: string): Promise<OperatorState> {
  try { await privateDirectory(dirname(path)); return parseState(JSON.parse((await boundedFile(path, 64 << 10, true)).toString("utf8"))); }
  catch (error) { if (error instanceof RelayError) throw error; throw failure("operator state could not be read securely"); }
}
export async function initializeOperatorState(path: string, value: OperatorState): Promise<void> {
  try {
    const state = parseState(value); await privateDirectory(dirname(path), true); await noLinks(path);
    const file = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await file.writeFile(JSON.stringify(state) + "\n"); await file.sync(); } finally { await file.close(); }
  } catch (error) { if (error instanceof RelayError) throw error; throw failure("operator state initialization failed; existing state is never overwritten"); }
}
async function processIdentity(pid: number): Promise<string | null> {
  try {
    process.kill(pid, 0);
    const { stdout } = await exec("/bin/ps", ["-p", String(pid), "-o", "lstart="], { timeout: 3000, maxBuffer: 4096, env: { ...process.env, LC_ALL: "C", TZ: "UTC" } });
    return stdout.trim() || null;
  } catch (error) { if (isError(error, "ESRCH") || (error as { code?: number }).code === 1) return null; throw failure("operator lock owner could not be verified"); }
}
const claimSchema = z.object({ pid: z.number().int().positive(), start: z.string().min(1).max(128), number: z.number().int().safe().nonnegative(), choosing: z.boolean(), name: hex(32) }).strict();
type Claim = z.infer<typeof claimSchema>;
// Bakery locking avoids the stale-lock unlink/recreate race: participants only
// update their own unique claim. PID plus start time identifies crashed owners;
// elapsed time never authorizes evicting a live writer.
async function withLock<T>(statePath: string, operation: () => Promise<T>): Promise<T> {
  await privateDirectory(dirname(statePath));
  const directory = `${statePath}.locks`; await privateDirectory(directory, true);
  const name = randomBytes(16).toString("hex"); const path = join(directory, name);
  const start = await processIdentity(process.pid); if (!start) throw failure("operator process identity is unavailable");
  const own: Claim = { pid: process.pid, start, number: 0, choosing: true, name };
  async function claims(): Promise<Claim[]> {
    const names = await readdir(directory); if (names.length > 256) throw failure("too many operator lock claims");
    const active: Claim[] = [];
    for (const entry of names) {
      if (/^\.[a-f0-9]{32}\.[a-f0-9]{24}\.tmp$/.test(entry)) continue;
      if (!/^[a-f0-9]{32}$/.test(entry)) throw failure("unexpected operator lock file");
      let claim: Claim;
      try {
        const parsed = claimSchema.safeParse(JSON.parse((await boundedFile(join(directory, entry), 4096, true)).toString("utf8")));
        if (!parsed.success || parsed.data.name !== entry) throw failure("invalid operator lock claim"); claim = parsed.data;
      } catch (error) { if (isError(error, "ENOENT")) continue; throw error; }
      if (claim.name !== name && await processIdentity(claim.pid) !== claim.start) { await rm(join(directory, entry), { force: true }); continue; }
      active.push(claim);
    }
    return active;
  }
  await atomicJson(path, own);
  try {
    own.number = Math.max(0, ...(await claims()).map((claim) => claim.number)) + 1;
    if (!Number.isSafeInteger(own.number)) throw failure("operator lock sequence exhausted");
    own.choosing = false; await atomicJson(path, own);
    const deadline = Date.now() + 60_000;
    while ((await claims()).some((claim) => claim.name !== name && (claim.choosing || (claim.number > 0 && (claim.number < own.number || (claim.number === own.number && claim.name < name)))))) {
      if (Date.now() > deadline) throw failure("another operator preparation is still running");
      await new Promise((done) => setTimeout(done, 30));
    }
    return await operation();
  } finally { await rm(path, { force: true }); }
}
async function decodePlist(input: string, limit: number): Promise<unknown> {
  const child = execFile("/usr/bin/plutil", ["-convert", "json", "-o", "-", "--", "-"], { timeout: 5000, maxBuffer: limit });
  return new Promise((done, reject) => {
    let output = ""; child.stdout?.setEncoding("utf8"); child.stdout?.on("data", (chunk: string) => { output += chunk; if (output.length > limit) child.kill(); }); child.on("error", reject);
    child.on("close", (code) => { try { if (code !== 0 || output.length > limit) throw failure("volume metadata could not be decoded"); done(JSON.parse(output)); } catch { reject(failure("volume metadata could not be decoded")); } }); child.stdin?.end(input);
  });
}
export async function probeMacVolume(directory: string): Promise<VolumeIdentity | null> {
  await noLinks(directory); const parent = dirname(directory); if (!(await exists(parent))) return null;
  if (process.platform !== "darwin") throw failure("the optional volume binding requires macOS");
  try {
    const { stdout } = await exec("/usr/sbin/diskutil", ["info", "-plist", parent], { timeout: 5000, maxBuffer: 64 << 10 });
    const parsed = await decodePlist(stdout, 64 << 10) as Record<string, unknown>;
    if (typeof parsed.VolumeUUID !== "string" || typeof parsed.MountPoint !== "string" || typeof parsed.DeviceIdentifier !== "string" || parsed.Mounted === false) throw failure("volume identity is unavailable");
    const [registry, boot] = await Promise.all([
      exec("/usr/sbin/ioreg", ["-a", "-r", "-c", "IOMedia"], { timeout: 5000, maxBuffer: 4 << 20 }),
      exec("/usr/sbin/sysctl", ["-n", "kern.bootsessionuuid"], { timeout: 3000, maxBuffer: 4096 }),
    ]);
    const bootId = boot.stdout.trim().toLowerCase(); if (!/^[a-f0-9-]{36}$/.test(bootId)) throw failure("boot identity is unavailable");
    const pending: unknown[] = [await decodePlist(registry.stdout, 4 << 20)]; const identities: number[] = [];
    while (pending.length) {
      const value = pending.pop(); if (!value || typeof value !== "object") continue;
      if (Array.isArray(value)) { pending.push(...value); continue; }
      const object = value as Record<string, unknown>;
      if (object["BSD Name"] === parsed.DeviceIdentifier && Number.isSafeInteger(object.IORegistryEntryID) && Number(object.IORegistryEntryID) > 0) identities.push(Number(object.IORegistryEntryID));
      pending.push(...Object.values(object));
    }
    if (identities.length !== 1) throw failure("volume incarnation could not be identified uniquely");
    return { uuid: parsed.VolumeUUID, mountPoint: parsed.MountPoint, external: parsed.Internal === false || parsed.DeviceLocation === "External", writable: parsed.Writable === true || parsed.ReadOnlyVolume === false, incarnation: `${bootId}:${identities[0]}` };
  } catch (error) { if (error instanceof RelayError) throw error; throw failure("volume identity could not be verified"); }
}
export class OperatorManager {
  private readonly origin: string; private readonly request: typeof fetch;
  private readonly probe: (directory: string) => Promise<VolumeIdentity | null>; private readonly now: () => number;
  constructor(private readonly statePath: string, rendezvousUrl: string, private readonly options: OperatorOptions = {}) {
    this.origin = configuredOrigin(rendezvousUrl); this.request = options.fetch ?? fetch; this.probe = options.volumeProbe ?? probeMacVolume; this.now = options.now ?? Date.now;
  }
  private async locked<T>(operation: (state: OperatorState) => Promise<T>): Promise<T> {
    try { return await withLock(this.statePath, async () => { const state = await readOperatorState(this.statePath); if (state.rendezvous_url !== this.origin) throw failure("operator state belongs to a different rendezvous"); return operation(state); }); }
    catch (error) { if (error instanceof RelayError) throw error; throw failure("operator trust operation failed"); }
  }
  private async pin(state: OperatorState, target: Session): Promise<void> {
    if (state.preparation || !state.expected_ticket_id || state.expected_ticket_id !== target.ticket_id) throw failure("session does not belong to the configured package");
    const identity = targetIdentity(target);
    if (state.pinned_identity === identity) return;
    if (state.pinned_identity) {
      const subsequent = state.ticket?.expires_at === null && target.sequence !== undefined && target.sequence > (state.pinned_sequence ?? 0);
      if (!subsequent) throw failure("the session changed or was replayed; connection refused");
    }
    // The Worker assigns an increasing sequence only after the previous session
    // has closed/expired. The publisher cannot choose or overwrite this value.
    state.pinned_identity = identity;
    if (target.sequence !== undefined) state.pinned_sequence = target.sequence;
    await atomicJson(this.statePath, state);
  }
  async authorizeSession(target: Session): Promise<void> { await this.locked((state) => this.pin(state, target)); }
  async dispatchAuthorized<T>(target: Session, dispatch: () => Promise<T>): Promise<T> {
    const started = await this.locked(async (state) => {
      await this.pin(state, target);
      // Invoke immediately while the trust lock is held, but do not hold that
      // lock until a potentially hour-long command completes.
      const outcome = dispatch().then((value) => ({ ok: true as const, value }), (error: unknown) => ({ ok: false as const, error }));
      return { outcome };
    });
    const result = await started.outcome; if (!result.ok) throw result.error; return result.value;
  }
  private async volume(state: OperatorState): Promise<VolumeIdentity | null> {
    const destination = state.package.directory;
    await noLinks(destination);
    if (this.statePath === destination || this.statePath.startsWith(destination + sep)) throw failure("package output must not contain the private operator state");
    if (destination === dirname(destination) || destination === homedir()) throw failure("choose a dedicated package directory, not a drive root or home directory");
    if (!state.package.volume_uuid) {
      const parent = dirname(destination);
      if (!(await exists(parent))) throw failure("create the package destination parent directory first");
      const info = await lstat(parent);
      if (!info.isDirectory()) throw failure("package destination parent is not a directory");
      if (await exists(destination) && !(await lstat(destination)).isDirectory()) throw failure("package path is not a directory");
      // Ordinary export supports any explicitly selected local directory. A
      // removable volume is optional; runtime MCP tools never inspect storage.
      return { uuid: "local-export", mountPoint: parent, external: false, writable: true, incarnation: `local:${info.dev}` };
    }
    const volume = await this.probe(destination); if (!volume) return null;
    if (volume.uuid.toLowerCase() !== state.package.volume_uuid.toLowerCase() || !volume.external || !volume.writable || !volume.incarnation || resolve(volume.mountPoint) !== dirname(destination)) throw failure("package volume does not match the trusted writable external volume");
    if (await exists(destination) && !(await lstat(destination)).isDirectory()) throw failure("package path is not a directory");
    return volume;
  }
  private async sources(state: OperatorState, volume: VolumeIdentity): Promise<Map<string, Buffer>> {
    const source = state.package.source_directory; await noLinks(source);
    if (await realpath(source) !== source || source === state.package.directory || source.startsWith(state.package.directory + sep) || state.package.directory.startsWith(source + sep) || (state.package.volume_uuid && (source === volume.mountPoint || source.startsWith(volume.mountPoint + sep)))) throw failure("package sources must come from the trusted source directory");
    const files = new Map<string, Buffer>();
    for (const name of PACKAGE_FILES) files.set(name, await boundedFile(join(source, name), 128 << 20));
    if (await exists(join(source, "cloudflared.exe"))) files.set("cloudflared.exe", await boundedFile(join(source, "cloudflared.exe"), 128 << 20));
    return files;
  }
  async prevalidate(): Promise<void> { await this.locked(async (state) => { const volume = await this.volume(state); if (!volume) throw failure("trusted package volume is not connected"); await this.sources(state, volume); }); }
  private async ticketRequest(state: OperatorState, method: "GET" | "POST", body?: unknown): Promise<Response> {
    try { return await this.request(`${this.origin}/ticket`, { method, redirect: "error", headers: { Authorization: `Bearer ${state.provision_key}`, ...(body ? { "Content-Type": "application/json" } : {}) }, ...(body ? { body: JSON.stringify(body) } : {}), signal: AbortSignal.timeout(10_000) }); }
    catch { throw failure("ticket service could not be reached securely"); }
  }
  private async ticketMetadata(state: OperatorState): Promise<z.infer<typeof ticketMetadataSchema> | null> {
    const response = await this.ticketRequest(state, "GET");
    if (response.status === 404) { await response.body?.cancel(); return null; }
    if (!response.ok) { await response.body?.cancel(); throw failure("ticket service refused preparation metadata"); }
    const parsed = ticketMetadataSchema.safeParse(await readJsonLimited(response, 4096));
    if (!parsed.success) throw failure("ticket service returned invalid metadata");
    return parsed.data;
  }
  private async prepareLocked(state: OperatorState, volume: VolumeIdentity, rotate: boolean): Promise<void> {
    const files = await this.sources(state, volume);
    if (!state.preparation) {
      if (rotate || !state.ticket) {
        state.ticket = { id: randomBytes(16).toString("hex"), secret: randomBytes(32).toString("hex"), expires_at: null, generation: 0 };
        delete state.pinned_identity; delete state.pinned_sequence;
      } else {
        // Upgrade/copy the same credential without disturbing a running session.
        state.ticket.expires_at = null;
      }
      state.version = 3; state.expected_ticket_id = state.ticket.id;
      state.preparation = { phase: "created" };
      await atomicJson(this.statePath, state); await this.options.afterPhase?.("intent");
    }
    const ticket = state.ticket!;
    if (state.preparation.phase === "created") {
      if (ticket.generation === 0) {
        const generation = (await this.ticketMetadata(state))?.generation ?? 0;
        ticket.generation = Math.max(generation, state.last_generation ?? 0) + 1;
        if (!Number.isSafeInteger(ticket.generation)) throw failure("ticket generation exhausted");
        state.last_generation = ticket.generation; await atomicJson(this.statePath, state);
      }
      const response = await this.ticketRequest(state, "POST", { ticket_id: ticket.id, ticket_hash: createHash("sha256").update(ticket.secret, "utf8").digest("hex"), expires_at: ticket.expires_at, generation: ticket.generation });
      if (!response.ok) { await response.body?.cancel(); throw failure("ticket service refused preparation; retry the same pending preparation"); }
      const receipt = ticketMetadataSchema.safeParse(await readJsonLimited(response, 4096));
      if (!receipt.success || receipt.data.ticket_id !== ticket.id || receipt.data.generation !== ticket.generation || receipt.data.expires_at !== ticket.expires_at || !(["pending", "claimed"] as string[]).includes(receipt.data.status)) throw failure("ticket preparation receipt does not confirm the persistent credential");
      state.preparation.phase = "registered"; await atomicJson(this.statePath, state); await this.options.afterPhase?.("registered");
    }
    // Resume by reconstructing from trusted sources, never by trusting a returned
    // package config or executable. Crash remnants and unknown files are preserved.
    const parent = dirname(state.package.directory);
    const stage = join(parent, `.${basename(state.package.directory)}.preparing-${randomBytes(12).toString("hex")}`); await mkdir(stage, { mode: 0o700 });
    for (const [name, data] of files) {
      const file = await open(join(stage, name), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
      try { await file.writeFile(data); await file.sync(); } finally { await file.close(); }
    }
    // Capability last; only a complete package is exposed by the rename.
    const config = { version: 3, url: this.origin, ticket_id: ticket.id, ticket_secret: ticket.secret, expires_at: ticket.expires_at };
    const configFile = await open(join(stage, "rendezvous.json"), constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
    try { await configFile.writeFile(JSON.stringify(config, null, 2) + "\n"); await configFile.sync(); } finally { await configFile.close(); }
    if ((await this.volume(state))?.incarnation !== volume.incarnation) throw failure("package volume changed during preparation");
    if (await exists(state.package.directory)) await rename(state.package.directory, join(parent, `${basename(state.package.directory)}.previous-${randomBytes(12).toString("hex")}`));
    await this.options.afterPhase?.("archived"); await rename(stage, state.package.directory); await this.options.afterPhase?.("installed");
    delete state.preparation; delete state.mounted; delete state.mounted_identity; await atomicJson(this.statePath, state);
  }
  /** Manual export only. Reuses the credential unless explicit rotation is requested. */
  async prepare({ force = false }: { force?: boolean } = {}): Promise<void> {
    await this.locked(async (state) => {
      const volume = await this.volume(state);
      if (!volume) throw failure("package destination is unavailable for this manual export");
      await this.prepareLocked(state, volume, force);
    });
  }
}
