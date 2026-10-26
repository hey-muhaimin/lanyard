export type GrantResource = { connector: string; actions: string[]; resource?: string; maxRows?: number };
export type GrantRequest = { subject: string; task: string; purpose?: string; resources: GrantResource[]; ttlSeconds?: number };
export type GrantResponse = { status: string; grant_id?: string; approval_id?: string; token?: string };

export class LanyardError extends Error {
  constructor(message: string, public status: number) { super(message.replace(/(?:Bearer|DPoP)\s+[A-Za-z0-9._~-]+/gi, '[REDACTED]')); }
}

export class PendingGrant {
  constructor(private readonly client: Lanyard, private readonly grant: GrantResponse) {}
  get approvalId() { return this.grant.approval_id; }
  async fetch(connector: string, path: string): Promise<Response> {
    if (!this.grant.token) throw new LanyardError('grant is pending approval', 202);
    return this.client.proxyFetch(connector, path, this.grant.token);
  }
}

export class Lanyard {
  constructor(private readonly controlPlaneURL: string, private readonly proxyURL: string) {}
  readonly grants = {
    request: async (request: GrantRequest): Promise<PendingGrant> => {
      const response = await fetch(`${this.controlPlaneURL}/grant`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(request) });
      if (!response.ok) throw new LanyardError(await response.text(), response.status);
      return new PendingGrant(this, await response.json() as GrantResponse);
    }
  };
  async proxyFetch(connector: string, path: string, token: string): Promise<Response> {
    return fetch(`${this.proxyURL}/proxy/${encodeURIComponent(connector)}${path.startsWith('/') ? path : '/' + path}`, { headers: { authorization: `Bearer ${token}`, 'x-lanyard-connector': connector } });
  }
}

export const testing = { inMemory: () => new Lanyard('http://lanyard.invalid', 'http://lanyard.invalid') };
