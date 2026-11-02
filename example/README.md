# End-to-End Agent Examples (Lanyard)

This directory contains five **example agents** to illustrate the complete flow.

## 1. Expected public key format
- Algorithm: **Ed25519**
- Export encoding (server): **Base64 URL-safe** (no padding), 32 bytes
- Server-side validation: `32 bytes` after decoding
- Private key material delivered by SDK:
  - `32-byte seed` (also encoded base64 URL-safe)
- The console offers a **"Generate and fill key pair"** button that creates the pair in your browser.

## 2. Generating a valid pair locally
Use Python to verify:

```bash
python -c "
import secrets, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
seed = secrets.token_bytes(32)
priv = Ed25519PrivateKey.from_private_bytes(seed)
pub = priv.public_key().public_bytes_raw()
print('PUBLIC_KEY_B64URL:', base64.urlsafe_b64encode(pub).rstrip(b'=').decode())
print('PRIVATE_SEED_B64URL:', base64.urlsafe_b64encode(seed).rstrip(b'=').decode())
"
```

Use the public key during registration; keep the seed in your agent environment.

## 3. Register an agent
From the customer console (or `POST /admin/agents`):
- id: `billing-agent` (must match `^[a-z0-9][a-z0-9-]{1,62}$`)
- owner_subject: `alice@example.com`
- public_key: the **base64url 32-byte public key**

## 4. End-to-end badge flow
1. **Register agent** with the public key (or use the web button).
2. **Issue a grant** from your backend (requires the agent seal).
   ```bash
   # agent signs with its seed:
   curl -X POST https://api.linkedqueue.cloud/grant      -H "Content-Type: application/json"      -H "DPoP: <EdDSA JWT explained in SDK>"      -d ...
   ```
5. The returned **PID** is an access token issued to your agent.
6. Call the gateway with `Authorization: Bearer <PID>`.

## 5. Included sample identities
See `seeds/agent-key-material.dev.json` for example Ed25519 seeds (dev-only).  
Do NOT use these keys in production.
