/**
 * Read-only client for DataForge's CSSA cloud-security ledger
 * (`DataForge#70`, `app/api/cloud_security_router.py`). Decisions-only per
 * the 2026-09-20 ruling -- `authorizations`/`outcomes` are not consumed by
 * this slice. `require_bearer` on that endpoint does not currently verify
 * the token (see `DataForge/docs/KNOWN_ISSUES.md`); this client still sends
 * one, since the header is required and a real credential is a separate,
 * later activation decision.
 */

export interface DataForgeCssaRecord {
  payload: unknown;
  record_hash: string;
}

export interface DataForgeCssaPage {
  items: DataForgeCssaRecord[];
  count: number;
  next_cursor: string | null;
}

export type FetchLike = (url: string, init?: { headers?: Record<string, string> }) => Promise<{
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}>;

export class DataForgeCssaClientError extends Error {
  constructor(readonly status: number, readonly body: string) {
    super(`DataForge cloud-security request failed: ${status} ${body}`.trim());
    this.name = "DataForgeCssaClientError";
  }
}

export interface DataForgeCssaClientOptions {
  baseUrl: string;
  bearerToken: string;
  fetchImpl?: FetchLike;
}

export class DataForgeCssaClient {
  private readonly fetchImpl: FetchLike;

  constructor(private readonly opts: DataForgeCssaClientOptions) {
    this.fetchImpl = opts.fetchImpl ?? (fetch as unknown as FetchLike);
  }

  async listDecisions(cursor: string | null, limit = 100): Promise<DataForgeCssaPage> {
    const url = new URL("/api/v1/cloud-security/decisions", this.opts.baseUrl);
    if (cursor) url.searchParams.set("cursor", cursor);
    url.searchParams.set("limit", String(limit));
    const response = await this.fetchImpl(url.toString(), {
      headers: { Authorization: `Bearer ${this.opts.bearerToken}` },
    });
    if (!response.ok) {
      const body = await response.text().catch(() => "");
      throw new DataForgeCssaClientError(response.status, body);
    }
    return (await response.json()) as DataForgeCssaPage;
  }
}
