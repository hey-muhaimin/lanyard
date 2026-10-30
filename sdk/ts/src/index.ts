export type GrantResource = { connector: string; action: string; resource: string; max_rows?: number };
export type GrantRequest = { subject: string; actor: string; task_id: string; purpose?: string; resources: GrantResource[]; ttl_seconds: number };
export type GrantResponse = { access_token?: string; token_type?: string; expires_in?: number; status?: string; grant_id?: string; approval_id?: string; token?: string };

const base64url = (bytes: Uint8Array): string =>
  btoa(String.fromCharCode(...bytes)).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

async function grantProof(seed: Uint8Array, targetURL: string): Promise<string> {
  if (seed.length !== 32) throw new TypeError('agent private key must be a 32-byte Ed25519 seed');
  const prefix = Uint8Array.from([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20]);
  const pkcs8 = new Uint8Array(prefix.length + seed.length);
  pkcs8.set(prefix);
  pkcs8.set(seed, prefix.length);
  const key = await globalThis.crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, true, ['sign']);
  const jwk = await globalThis.crypto.subtle.exportKey('jwk', key);
  if (!jwk.x) throw new Error('could not export agent public key');
  const header = { alg: 'EdDSA', typ: 'dpop+jwt', jwk: { kty: 'OKP', crv: 'Ed25519', x: jwk.x } };
  const claims = { htm: 'POST', htu: targetURL, iat: Math.floor(Date.now() / 1000), jti: globalThis.crypto.randomUUID() };
  const encoder = new TextEncoder();
  const unsigned = `${base64url(encoder.encode(JSON.stringify(header)))}.${base64url(encoder.encode(JSON.stringify(claims)))}`;
  const signature = new Uint8Array(await globalThis.crypto.subtle.sign('Ed25519', key, encoder.encode(unsigned)));
  return `${unsigned}.${base64url(signature)}`;
}

export class LanyardError extends Error {
  constructor(message: string, public status: number) { super(message.replace(/(?:Bearer|DPoP)\s+[A-Za-z0-9._~-]+/gi, '[REDACTED]')); }
}

export class PendingGrant {
  constructor(private readonly client: Lanyard, private readonly grant: GrantResponse) {}
  get approvalId() { return this.grant.approval_id; }
  async fetch(connector: string, path: string): Promise<Response> {
    const token = this.grant.access_token ?? this.grant.token;
    if (!token) throw new LanyardError('grant is pending approval', 202);
    return this.client.proxyFetch(connector, path, token);
  }
}

export class Lanyard {
  constructor(private readonly controlPlaneURL: string, private readonly proxyURL: string, private readonly agentPrivateKey?: Uint8Array) {}
  readonly grants = {
    request: async (request: GrantRequest): Promise<PendingGrant> => {
      if (!this.agentPrivateKey) throw new LanyardError('agent private key is required for grant requests', 0);
      const url = new URL('/grant', this.controlPlaneURL);
      const targetURL = `${url.protocol}//${url.host}${url.pathname}`;
      const proof = await grantProof(this.agentPrivateKey, targetURL);
      const response = await fetch(url, { method: 'POST', headers: { 'content-type': 'application/json', DPoP: proof }, body: JSON.stringify(request) });
      if (!response.ok) throw new LanyardError(await response.text(), response.status);
      return new PendingGrant(this, await response.json() as GrantResponse);
    }
  };
  async proxyFetch(connector: string, path: string, token: string): Promise<Response> {
    return fetch(`${this.proxyURL}/proxy/${encodeURIComponent(connector)}${path.startsWith('/') ? path : '/' + path}`, { headers: { authorization: `Bearer ${token}`, 'x-lanyard-connector': connector } });
  }
}

export const testing = { inMemory: () => new Lanyard('http://lanyard.invalid', 'http://lanyard.invalid') };
