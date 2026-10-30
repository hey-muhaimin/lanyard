import assert from 'node:assert/strict';
import { test } from 'node:test';
import { Lanyard } from '../dist/index.js';

const decodeBase64url = (value) => Buffer.from(value, 'base64url');

test('grant requests include a valid proof bound to the registered agent key', async () => {
  const originalFetch = globalThis.fetch;
  let requestOptions;
  globalThis.fetch = async (_url, options) => {
    requestOptions = options;
    return new Response(JSON.stringify({ access_token: 'test-token', token_type: 'Bearer', expires_in: 60 }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };

  try {
    const seed = new Uint8Array(32).fill(7);
    const client = new Lanyard('https://controlplane.example', 'https://proxy.example', seed);
    await client.grants.request({
      subject: 'user:alice',
      actor: 'agent:alice',
      task_id: 'task-1',
      ttl_seconds: 60,
      resources: [{ connector: 'crm', action: 'read', resource: 'accounts/1', max_rows: 10 }],
    });

    const [headerPart, claimsPart, signaturePart] = requestOptions.headers.DPoP.split('.');
    const header = JSON.parse(decodeBase64url(headerPart));
    const claims = JSON.parse(decodeBase64url(claimsPart));
    assert.equal(header.alg, 'EdDSA');
    assert.equal(header.typ, 'dpop+jwt');
    assert.equal(claims.htm, 'POST');
    assert.equal(claims.htu, 'https://controlplane.example/grant');
    assert.equal('ath' in claims, false);

    const publicKey = await globalThis.crypto.subtle.importKey(
      'raw', decodeBase64url(header.jwk.x), { name: 'Ed25519' }, false, ['verify']);
    const valid = await globalThis.crypto.subtle.verify(
      'Ed25519', publicKey, decodeBase64url(signaturePart), new TextEncoder().encode(`${headerPart}.${claimsPart}`));
    assert.equal(valid, true);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('grant requests fail locally without an agent key', async () => {
  const client = new Lanyard('https://controlplane.example', 'https://proxy.example');
  await assert.rejects(() => client.grants.request({
    subject: 'user:alice',
    actor: 'agent:alice',
    task_id: 'task-1',
    ttl_seconds: 60,
    resources: [{ connector: 'crm', action: 'read', resource: 'accounts/1' }],
  }), /agent private key is required/);
});