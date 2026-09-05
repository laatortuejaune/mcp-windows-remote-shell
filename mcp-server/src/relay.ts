import {
  CLIENT_MARGIN_MS, EXEC_RESPONSE_LIMIT, HEALTH_RESPONSE_LIMIT, REQUEST_LIMIT,
  SESSION_RESPONSE_LIMIT, RelayError, configuredOrigin, execSchema, healthSchema,
  httpBudgetMs, parseSession, readJsonLimited, tokenSchema,
  type Target, type Session,
} from "./security.js";

export type RelayConfig = {
  rendezvous?: { url: string; readKey: string };
  staticTarget?: { url: string; token: string };
  defaultTimeoutSeconds: number;
  httpTimeoutMs?: number;
};

// The production authorizer uses operator-owned state, never data from a target
// or the portable package. Dependency injection keeps transport tests isolated.
export interface SessionAuthorizer {
  authorizeSession(target: Session): Promise<void>;
  dispatchAuthorized<T>(target: Session, dispatch: () => Promise<T>): Promise<T>;
}

export class RelayClient {
  private readonly config: RelayConfig;
  constructor(config: RelayConfig, private readonly fetcher: typeof fetch = fetch,
    private readonly now = Date.now, private readonly authorizer?: SessionAuthorizer) {
    this.config = structuredClone(config);
    httpBudgetMs(config.defaultTimeoutSeconds, config.httpTimeoutMs);
    if (this.config.rendezvous) {
      this.config.rendezvous.url = configuredOrigin(this.config.rendezvous.url);
      if (!tokenSchema.safeParse(this.config.rendezvous.readKey).success) throw new RelayError("invalid rendezvous read key");
      if (!authorizer) throw new RelayError("automatic rendezvous requires the operator's prepared-ticket state");
    } else if (this.config.staticTarget) {
      this.config.staticTarget.url = configuredOrigin(this.config.staticTarget.url, true);
      if (!tokenSchema.safeParse(this.config.staticTarget.token).success) throw new RelayError("invalid static token");
      // Static configuration is supplied by the operator, never by a target.
    } else { throw new RelayError("configure rendezvous URL/read key or a static URL/token"); }
  }

  private async request(url: string, token: string, limit: number, timeoutMs: number, body?: string): Promise<unknown> {
    let response: Response;
    try {
      response = await this.fetcher(url, {
        method: body === undefined ? "GET" : "POST",
        headers: { Authorization: `Bearer ${token}`, ...(body === undefined ? {} : { "Content-Type": "application/json" }) },
        ...(body === undefined ? {} : { body }),
        redirect: "error", signal: AbortSignal.timeout(timeoutMs),
      });
    } catch {
      // Raw exceptions may contain credentials, URLs or untrusted text.
      throw new RelayError("request failed or timed out; check the relay connection (redirects are forbidden)");
    }
    if (response.redirected || response.status >= 300 && response.status < 400) {
      await response.body?.cancel();
      throw new RelayError("HTTP redirects are forbidden");
    }
    if (!response.ok) {
      await response.body?.cancel();
      if (response.status === 401) throw new RelayError("credentials rejected (401)");
      if (response.status === 404) throw new RelayError("no active session or relay endpoint (404)");
      throw new RelayError(`relay returned HTTP ${response.status}`);
    }
    return readJsonLimited(response, limit);
  }

  private async resolveTarget(): Promise<Target> {
    if (this.config.rendezvous) {
      const { url, readKey } = this.config.rendezvous;
      const value = await this.request(new URL("/session", url).href, readKey, SESSION_RESPONSE_LIMIT, 10_000);
      return parseSession(value, this.now());
    }
    return { ...this.config.staticTarget! };
  }
  private async assertAuthorized(target: Target): Promise<void> {
    if (target.expires_at && Date.parse(target.expires_at) <= this.now()) throw new RelayError("session has expired");
    if (this.config.rendezvous) await this.authorizer!.authorizeSession(parseSession(target, this.now()));
  }
  private async dispatchAuthorized<T>(target: Target, dispatch: () => Promise<T>): Promise<T> {
    if (!this.config.rendezvous) return dispatch();
    return this.authorizer!.dispatchAuthorized(parseSession(target, this.now()), dispatch);
  }
  private redact(text: string, target: Target): string {
    for (const secret of [target.token, this.config.rendezvous?.readKey]) {
      if (secret) text = text.replaceAll(secret, "[redacted]");
    }
    return text;
  }

  async currentTarget(): Promise<string> {
    const target = await this.resolveTarget();
    await this.assertAuthorized(target);
    const text = [
      `mode: ${this.config.rendezvous ? "rendezvous" : "static"}`,
      `connection: ${this.config.rendezvous ? "automatic (prepared package verified)" : "operator configuration"}`,
      `url: ${target.url}`,
      `host (reported, not an identity proof): ${target.host || "(unknown)"}`,
      `os: ${target.os || "(unknown)"}`,
      `published_at: ${target.published_at || "(n/a)"}`,
      `expires_at: ${target.expires_at || "(static configuration)"}`,
    ].join("\n");
    return this.redact(text, target);
  }
  async checkAgent(): Promise<string> {
    const target = await this.resolveTarget();
    await this.assertAuthorized(target);
    const value = await this.dispatchAuthorized(target, () => this.request(
      new URL("/health", target.url).href, target.token, HEALTH_RESPONSE_LIMIT, CLIENT_MARGIN_MS,
    ));
    const parsed = healthSchema.safeParse(value);
    if (!parsed.success) throw new RelayError("invalid agent health response; update the agent");
    return this.redact(`agent OK via ${target.url}\n${JSON.stringify(parsed.data)}`, target);
  }
  async runCommand(command: string, timeoutSeconds?: number): Promise<string> {
    if (typeof command !== "string" || !command.trim() || Buffer.byteLength(command) > REQUEST_LIMIT) {
      throw new RelayError("command is empty or exceeds the request size limit");
    }
    const target = await this.resolveTarget();
    await this.assertAuthorized(target);
    // Always send an explicit timeout, independent of the remote agent default.
    const seconds = timeoutSeconds ?? this.config.defaultTimeoutSeconds;
    const budget = httpBudgetMs(seconds, this.config.httpTimeoutMs);
    const body = JSON.stringify({ command, timeout_seconds: seconds });
    if (Buffer.byteLength(body) > REQUEST_LIMIT) throw new RelayError("encoded command exceeds the request size limit");
    // The final authorization and start of the HTTP request share the operator
    // lock. A concurrent preparation cannot switch the expected ticket between
    // the check and dispatch. Already dispatched commands may still finish.
    const value = await this.dispatchAuthorized(target, () => this.request(
      new URL("/exec", target.url).href, target.token, EXEC_RESPONSE_LIMIT, budget, body,
    ));
    const parsed = execSchema.safeParse(value);
    if (!parsed.success) throw new RelayError("invalid agent execution response");
    const result = parsed.data;
    return this.redact(`exit_code=${result.exit_code} timed_out=${result.timed_out} truncated=${result.truncated} duration_ms=${result.duration_ms}\n--- stdout ---\n${result.stdout || "(empty)"}\n--- stderr ---\n${result.stderr || "(empty)"}`, target);
  }
}
