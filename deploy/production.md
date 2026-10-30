# Production Rollout

## Runtime inputs

Store the Compose interpolation values in a root-owned file with mode `0600`; keep secret values in Secrets Manager and provide only their ARNs:

- `TENANT_ID`: the tenant UUID already present in PostgreSQL
- `DATABASE_SECRET_ARN`: RDS-managed PostgreSQL master secret ARN
- `TOKEN_PRIVATE_KEY_SECRET_ARN`: Secrets Manager secret containing a base64url Ed25519 seed
- `UPSTREAM_SECRET_ARN`: Secrets Manager string secret containing the connector credential
- `TOKEN_PUBLIC_KEY_SECRET_ARN`: Secrets Manager secret containing the base64url Ed25519 public key
- `TOKEN_KEY_ID`, `TOKEN_ISSUER`, `TOKEN_AUDIENCE`
- `UPSTREAM_URL`: fixed HTTPS endpoint without credentials, query, or fragment
- `PROXY_CONNECTOR_ID`, `PROXY_SECRET_ID`
- `LANYARD_IMAGE`: unique image tag derived from the source archive SHA-256

The EC2 role must have only the required secret reads, KMS data-key operations for `purpose=secret`, S3 artifact reads, and SSM management permissions. RDS is non-public and accepts PostgreSQL only from the Lanyard instance security group. The Compose ports bind to loopback; no database, NATS, or public application ports are published.

## Rollout

1. Build the image from the verified source archive on the controlled EC2 host and assign an immutable source-hash tag.
2. Record the currently running image tag and Compose configuration for rollback.
3. Run `/app/migrate` once with the production environment file; verify migration history and tenant-scoped data.
4. Start the new image with `docker compose --env-file /etc/lanyard/production.env -f /opt/lanyard/production.compose.yml up -d`.
5. Verify `http://127.0.0.1:8080/healthz`, `/readyz`, and the corresponding proxy health/readiness endpoints through SSM.
6. Confirm RDS is non-public, encrypted, Multi-AZ, protected from deletion, and reachable only from the app security group.

## Rollback

If readiness or smoke checks fail, restore the previous immutable `LANYARD_IMAGE` tag and run the same Compose `up -d` command. Do not delete the RDS instance or its data. Schema changes must remain backward-compatible with the previous image; otherwise restore the database from its pre-deploy snapshot before rolling back the application.