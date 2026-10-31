# Deployment Status and Rollout Notes

> **Do not treat this repository as production-ready.** These notes describe a manual single-host deployment template, not a completed or approved production architecture. The CDK stack in `cdk/` is a prototype and must not be deployed as-is.

## Current Release Blockers

- Customer authentication defaults to `AUTH_CODE_DELIVERY=none`; no production email/code delivery provider is implemented. Do not enable plaintext login-code logging as a workaround.
- The customer console is built as a static export, but the CDK distribution does not currently route its customer API paths to the control plane.
- The CDK prototype uses a public HTTP load balancer, destructive removal policies, placeholder secrets and tenant settings, and does not run the proxy service.
- The ops UI is a prototype. Its former placeholder API used dummy sessions; `/ops/*` is intentionally not mounted until staff authentication and authorization are complete.
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

The EC2 role must have only the required secret reads, KMS data-key operations for `purpose=secret`, S3 artifact reads, and SSM management permissions. RDS must be non-public and accept PostgreSQL only from the Lanyard instance security group. The current Compose file pins `AWS_REGION` to `ap-southeast-2`; verify that this matches the project's selected Region before use. The Compose ports bind to loopback; no database, NATS, or public application ports are published.

## Rollout

1. Do not start a launch rollout until the release blockers above are closed. For a controlled deployment exercise, build the image from the verified source archive on the host and assign an immutable source-hash tag.
2. Record the currently running image tag and Compose configuration for rollback.
3. Run `/app/migrate` once with the production environment file; verify migration history and tenant-scoped data.
4. Start the new image with `docker compose --env-file /etc/lanyard/production.env -f /opt/lanyard/production.compose.yml up -d`.
5. Verify `http://127.0.0.1:8080/healthz`, `http://127.0.0.1:8080/readyz`, and the corresponding proxy health/readiness endpoints through SSM. These checks alone do not prove customer login, console routing, or production readiness.
6. Confirm RDS is non-public, encrypted, Multi-AZ, protected from deletion, and reachable only from the app security group.

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