# Deployment Status and Rollout Notes

> **Do not treat this repository as production-ready.** These notes describe a manual single-host deployment template, not a completed or approved production architecture. The CDK stack in `cdk/` is a prototype and must not be deployed as-is.

## Current Release Blockers

- Customer login-code delivery is implemented for SES (`AUTH_CODE_DELIVERY=email`) but is not
  provisioned by this template: it needs a verified SES identity, the `ses:SendEmail` grants in
  [../infra/iam/README.md](../infra/iam/README.md), and `AUTH_EMAIL_FROM` on a verified domain.
  Until those exist `/auth/request` returns `503` rather than claiming a code was sent. Never
  enable plaintext login-code logging as a workaround.
- The customer console is built as a static export, but the CDK distribution does not currently route its customer API paths to the control plane.
- The CDK prototype uses a public HTTP load balancer, destructive removal policies, placeholder secrets and tenant settings, and does not run the proxy service.
- The ops console is still a prototype UI, but its backend now exists: `/ops/*` is mounted only
  when `OPS_SSO_ENABLED=true` and backed by Cognito authorization-code + PKCE. It is not approved
  for production until the hosting, network allowlist, and staff-group membership below are
  reviewed. The former placeholder handler stays deleted; do not re-add it.
- DPoP replay detection and revocation propagation are not suitable for multi-replica production use yet.

Close these gaps and run the security, recovery, load, and operational acceptance checks before launch.

## Manual Single-Host Template

The Compose file below binds both service ports to host loopback. Put it behind a separately configured TLS ingress and restrict host access. It does not configure or provision that ingress, PostgreSQL, backups, monitoring, or customer-console hosting.

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
- `PUBLIC_BASE_URL`: the customer console origin (e.g. `https://console.linkedqueue.cloud`); used
  by the tenant cookie and origin checks
- `AUTH_CODE_DELIVERY`: `email` (default in the template), `none`, or the dev-only `log`/`response`
- `AUTH_EMAIL_FROM`: SES `FromEmailAddress` on a verified identity (default `no-reply@linkedqueue.cloud`)
- `OPS_SSO_ENABLED`: `true` to mount `/ops/*` behind Cognito; `false` keeps every `/ops/*` path at 404
- `COGNITO_SECRET_ARN`: ARN of the `production/lanyard/cognito` secret (required when SSO is on)
- `OPS_PUBLIC_BASE_URL`: the ops console origin (e.g. `https://ops.linkedqueue.cloud`); the cookie
  `Secure` flag and the write-origin check derive from it

The EC2 role must have only the required secret reads, KMS data-key operations for `purpose=secret`, S3 artifact reads, and SSM management permissions. RDS must be non-public and accept PostgreSQL only from the Lanyard instance security group. The current Compose file pins `AWS_REGION` to `ap-southeast-2`; verify that this matches the project's selected Region before use. The Compose ports bind to loopback; no database, NATS, or public application ports are published.

## Rollout

1. Do not start a launch rollout until the release blockers above are closed. For a controlled deployment exercise, build the image from the verified source archive on the host and assign an immutable source-hash tag.
2. Record the currently running image tag and Compose configuration for rollback.
3. Run `/app/migrate` once with the production environment file; verify migration history and tenant-scoped data.
4. Confirm the new migrations applied: `ops_members.cognito_sub`, `ops_sessions.hardware_key`, and
   `ops_list_tenants()` (`psql -c '\df ops_list_tenants'`). Re-running `/app/migrate` must report
   "database migrations are up to date".
5. Only when `OPS_SSO_ENABLED=true`: apply the SES/IAM changes in `infra/iam/README.md`, then check
   that `GET /ops/auth/login` returns a `302` to the Cognito hosted UI and that `GET /ops/health`
   without a cookie returns `401`.
6. Start the new image with `docker compose --env-file /etc/lanyard/production.env -f /opt/lanyard/production.compose.yml up -d`.
7. Verify `http://127.0.0.1:8080/healthz`, `http://127.0.0.1:8080/readyz`, and the corresponding proxy health/readiness endpoints through SSM. These checks alone do not prove customer login, console routing, or production readiness.
8. Confirm RDS is non-public, encrypted, Multi-AZ, protected from deletion, and reachable only from the app security group.

## Rollback

If readiness or smoke checks fail, restore the previous immutable `LANYARD_IMAGE` tag and run the same Compose `up -d` command. Do not delete the RDS instance or its data. Schema changes must remain backward-compatible with the previous image; otherwise restore the database from its pre-deploy snapshot before rolling back the application.

## Verified Deployment (2026-10-31)

- Source archive: `releases/lanyard-source-674509ffb90f48fe406653f7764007ce999f5ee2dd172ab84b6ff4e66435596d.zip` in the deployment bucket. Its SHA-256 is `674509ffb90f48fe406653f7764007ce999f5ee2dd172ab84b6ff4e66435596d`; upload used a conditional no-overwrite request and AES-256 server-side encryption.
- Runtime image: `lanyard-production-674509ffb90f48fe406653f7764007ce999f5ee2dd172ab84b6ff4e66435596d`, image ID `sha256:314a69079dbb079d514eae9221d0565201d7289a36eeed387b79c55b17dcd62e`, `linux/arm64`. A compressed image archive is retained on the controlled host with SHA-256 `9b6d851d8ff24a1ca884f07ef9fe20d5e2bf5a7815f1b582332f1854ea9e3cbf`; it has not been uploaded to S3.
- Rollback: prior image tag `lanyard-production-20261031-5` remains on the host. The original Compose file is preserved as `production.compose.yml.rollback-lanyard-production-20261031-5`.
- Data: the private RDS instance was already populated. Tenant-scoped verification found one tenant, one active agent, one connector, one published policy, and one active encrypted vault secret. The two old local Docker volumes contained no application rows, so no restore/import was run. The migration-history table exists; the runtime database role cannot read its version rows.
- Backups: AWS Backup plan `lanyard-rds-daily-7d` targets only the Lanyard RDS instance, runs daily at 02:00 UTC, and retains recovery points for seven days. The pre-deployment recovery point completed successfully and is encrypted. The plan and role configuration are in `infra/aws-backup/` and `infra/iam/`.
- Runtime KMS boundary: the EC2 role now uses `lanyard-ec2-ssm-runtime-boundary-v1`, which allows only `kms:GenerateDataKey` and `kms:Decrypt` on the Lanyard vault key with `kms:EncryptionContext:purpose=secret`. The previously shared boundary remains unchanged for its other principals.
- Ingress: no security-group inbound rules were added. Control-plane and proxy host ports remain bound to loopback and were verified through SSM. `/ops/*` remains unavailable.

This remains a controlled single-host deployment, not a production launch approval. The RDS instance is private and encrypted but remains single-AZ, its native automated-backup retention is one day, deletion protection is disabled, and storage uses an AWS-managed RDS key. The AWS Backup plan adds seven-day scheduled recovery points, but a restore test has not been run. Resolve the availability/deletion-protection gaps and test restoration before broader production use.

## Verified Deployment (2026-10-31)

- Source archive: `releases/lanyard-source-674509ffb90f48fe406653f7764007ce999f5ee2dd172ab84b6ff4e66435596d.zip` in the deployment bucket. Its SHA-256 is `674509ffb90f48fe406653f7764007ce999f5ee2dd172ab84b6ff4e66435596d`; upload used a conditional no-overwrite request and the bucket's AES-256 server-side encryption.
- Runtime image: `lanyard-production-674509ffb90f48fe406653f7764007ce999f5ee2dd172ab84b6ff4e66435596d`, image ID `sha256:314a69079dbb079d514eae9221d0565201d7289a36eeed387b79c55b17dcd62e`, `linux/arm64`. A compressed image archive is retained on the controlled host with SHA-256 `9b6d851d8ff24a1ca884f07ef9fe20d5e2bf5a7815f1b582332f1854ea9e3cbf`.
- Rollback: prior image tag `lanyard-production-20261031-5` remains on the host. The original Compose file is preserved as `production.compose.yml.rollback-lanyard-production-20261031-5`.
- Data: the private RDS instance was already populated. Tenant-scoped verification found one tenant, one active agent, one connector, one published policy, and one active encrypted vault secret. The two old local Docker volumes contained no application rows, so no restore/import was run. The migration-history table exists; the runtime database role cannot read its version rows.
- Backups: AWS Backup plan `lanyard-rds-daily-7d` targets only the Lanyard RDS instance, runs daily at 02:00 UTC, and retains recovery points for seven days. The pre-deployment recovery point completed successfully and is encrypted. The plan and role configuration are in `infra/aws-backup/` and `infra/iam/`.
- Runtime KMS boundary: the EC2 role now uses `lanyard-ec2-ssm-runtime-boundary-v1`, which allows only `kms:GenerateDataKey` and `kms:Decrypt` on the Lanyard vault key with `kms:EncryptionContext:purpose=secret`. The previously shared boundary remains unchanged for its other principals.
- Ingress: no security-group inbound rules were added. Control-plane and proxy host ports remain bound to loopback and were verified through SSM. `/ops/*` remains unavailable.

This is a controlled single-host deployment, not a production launch approval. The RDS instance remains single-AZ, its native automated-backup retention is one day, deletion protection is disabled, and storage uses an AWS-managed RDS key. Plan the required availability and deletion-protection changes before broader production use; test a restore from the new AWS Backup plan before relying on it as the sole recovery path.

## Ops console SSO and hosting

The ops UI is a static export served from its own internal origin. It calls `/ops/*` on the same
origin, so the host must proxy those paths to the control plane.

1. Cognito app client (already provisioned as `production/lanyard/cognito`): confidential client,
   authorization-code grant, scopes `openid email profile`, callback URLs
   `https://ops.linkedqueue.cloud/ops/auth/callback/` and
   `http://localhost:8080/ops/auth/callback/` (the trailing slash is required), sign-out URL
   `https://ops.linkedqueue.cloud/`. Staff are members of the `staff` group; membership is what
   authorizes access. New members are provisioned in `ops_members` as read-only `ops_support`;
   promotion to `ops_oncall`/`ops_admin` is a manual `UPDATE ops_members SET role = ...`.
2. Host rewrite rule (Amplify console → Rewrites and redirects, JSON form). Replace the target host
   with the control plane's public origin; keep status `200` so it is a proxy rewrite, not a redirect:

   ```json
   [
     {
       "source": "/ops/<*>",
       "target": "https://console.linkedqueue.cloud/ops/<*>",
       "status": "200",
       "condition": null
     }
   ]
   ```

   The rewrite forwards the browser's `Origin` header, so `OPS_PUBLIC_BASE_URL` must be the ops
   origin (`https://ops.linkedqueue.cloud`), not the control plane host. Responses keep their
   `Set-Cookie` on the ops origin because the browser sees a same-origin response.
3. Local development: `cd web/ops && LANYARD_API_ORIGIN=http://localhost:8080 npm run dev` uses the
   Next dev rewrite (`web/ops/next.config.mjs`). `NEXT_PUBLIC_OPS_MOCK=1` is fixtures only.
4. Do not expose `/ops/*` on the public customer listener. Keep the ops host on an internal network
   or behind an allowlist.

## Rollback for this change

`006_ops_sso.sql` and `007_ops_tenants.sql` are additive except for
`ops_create_session`/`ops_get_session`, which are replaced. No previously shipped image calls those
functions (the ops handler was never mounted), so rolling back to the previous image is safe without
a database restore. Rolling back only the application leaves the new columns and function in place,
which the previous image ignores.