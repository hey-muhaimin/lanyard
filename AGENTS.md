## Project Guide

Lanyard is a Go control plane and egress proxy for task-scoped agent grants. The repository is not production-ready; use [README.md](README.md) for current status, setup, and known release blockers. Treat proposals and sprint notes as historical unless the README or current code confirms them.

## Quick Checks

- Go: `go test ./...` and `go build ./...` (Go 1.27).
- Cedar: `cedar validate --schema policies/schema.cedarschema.json --schema-format json --policies policies/default.cedar --policy-format cedar`.
- Customer UI: from `web/console`, run `npm ci`, `npm run typecheck`, `npm test`, and `npm run build:static` (Node 20.9+).
- Ops UI: from `web/ops`, run `npm ci`, `npm run typecheck`, `npm test`, and `npm run build:static` (Node 20.9+). Mock mode is not production auth.
- CI is defined in `.github/workflows/ci.yml`; database integration checks require its PostgreSQL setup or the documented local test URLs.

## Repository Rules

- Do not use demo mode or demo credentials in production. Tenant IDs stored in PostgreSQL must be UUIDs; the default `tenant-demo` is local-only and the demo agent seed is not compatible with the production UUID schema.
- Never log request bodies, authorization headers, login codes, tokens, or upstream secrets. Keep secrets in the configured secret store, not source or Compose files.
- Treat migrations as immutable after release. Add the next contiguous migration and preserve RLS, tenant scoping, and explicit grants for tenant-owned tables.
- Keep production access fail-closed. `/ops/*` is intentionally not mounted until real staff authentication and authorization are implemented. Do not re-enable the placeholder handler.
- The root `docker-compose.yml` is not a supported production deployment. `deploy/production.compose.yml` is a manual single-host template, not an endorsement that the whole product is production-ready.
- Avoid committing generated binaries, local environment files, node modules, or static build output. Some historical artifacts are already tracked; do not delete or rewrite those without an explicit cleanup decision.

## Layout

- `cmd/controlplane`, `cmd/proxy`, `cmd/migrate`: service and migration entry points.
- `internal/`: auth, grants, policy, storage, vault, proxy support, and logging.
- `migrations/`: embedded PostgreSQL migrations; `policies/`: Cedar schema and example policy.
- `web/console`: customer console; `web/ops`: internal console prototype; `web/`: legacy static assets.
- `deploy/`: single-host Compose template and rollout notes; `cdk/`: infrastructure prototype, not approved for production deployment.
- `sdk/`, `connectors/`, `docs/`: client code, connector specifications, and design records.

## Email login-code delivery (new)

- Enable with `AUTH_CODE_DELIVERY=email`.
- `AUTH_EMAIL_FROM` (default `no-reply@linkedqueue.cloud`) must be a non‑empty valid email address; the control‑plane validates this at start.
- Requires `AWS_REGION` (SES region). The mailer is created at startup; if SES init fails a warning is logged and email delivery is disabled.
- Run mailer‑specific tests: `go test ./internal/mailer`.
- When `AUTH_CODE_DELIVERY=response` is used, `ALLOW_INSECURE_DEMO` must be true (dev mode only).

## Ops staff SSO (new)

- Enable with `OPS_SSO_ENABLED=true`.
- Requires `COGNITO_SECRET_ARN` and `OPS_PUBLIC_BASE_URL` (HTTPS unless dev mode). In dev mode (`ALLOW_INSECURE_DEMO=true`) HTTP is allowed.
- When enabled, `/ops/*` routes are mounted; otherwise they return 404.
- Registration endpoint is gated by `ALLOW_SIGNUP`.

## IAM / Permissions Boundary (new)

- Apply the SES send‑email policy located at `infra/iam/lanyard-ses-send-policy.json`:
  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Sid": "AllowSendEmail",
        "Effect": "Allow",
        "Action": ["ses:SendEmail"],
        "Resource": "arn:aws:ses:ap-southeast-2:459321894716:identity/linkedqueue.cloud"
      }
    ]
  }
  ```
- Update the EC2 role boundary `lanyard-ec2-ssm-runtime-boundary-v1` to include the `AllowSendEmail` statement (see the same file for the snippet). Publish a new version and set it as default:
  ```
  aws iam create-policy-version \
    --policy-arn arn:aws:iam::459321894716:policy/lanyard-ec2-ssm-runtime-boundary-v1 \
    --policy-document file://infra/iam/lanyard-ec2-ssm-runtime-boundary.json \
    --set-as-default
  ```
- Attach both the identity policy and the updated boundary to the EC2 instance role that runs the control‑plane container.
<!-- BEGIN AWS Agent Toolkit rules -->
<!-- BEGIN AWS Agent Toolkit rules -->
# AWS Guidance for the new AWS experience

This user has signed up for the new AWS experience. This experience lets you sign into AWS using a social provider and requires the following additional context.

*When this guidance conflicts with the project's own instructions, the project's instructions take precedence.*

## Context

### Terminology:

- Say "project" instead of "account" — a project contains an AWS account and settings for sharing with other collaborators
- Say "team member" instead of "IAM user" — users are invited by email, not created or federated in IAM
- Say "AWS Settings" when referring to management tasks at https://settings.aws.com/ (project management, billing, team members, spend limits). Users view their actual AWS resources in the AWS Management Console.
- Say "selected Region" when referring to the user's Region — not "home Region"
- The user has a managed IAM experience. This includes a managed service control policies (SCP) and resource control policies (RCP) that govern the use of AWS. They will still need to use IAM to create policies to let services work with each other. If there are questions about the SCPs or RCPs, go to the documentation at https://docs.aws.amazon.com/accounts/latest/reference/scps-and-rcps-for-projects.html

### Constraints:

- All projects share a single AWS Region determined by the user's contact address. Resources cannot be created in other Regions
- When developing:
  - **MUST** create all Regional resources in the project's assigned Region
  - You **CAN** create AWS WAF and CloudWatch Logs resources in us-east-1 when there are global resources (like a global WAF instance) that require a connection to dependencies in us-east-1. You should not use these for any other reason, because resources in the selected Region will provide lower cost, higher availability, and easier manageability.
  - **MUST NOT** attempt to create Lambda, API Gateway, or other Regional resources in any other Region
  - **MUST** direct users to confirm their Region in AWS Settings > View all projects > Overview > Additional Info > Region. If the user cannot confirm their Region, check `~/.aws/config`
  - **MUST NOT** use Lambda@Edge — excluded from both Lambda and CloudFront
  - **MUST NOT** use CloudFormation StackSets — no multi‑account or multi‑Region deployments
  - **MUST NOT** attempt cross‑Region actions — no cross‑Region replication for DynamoDB/S3/RDS, no multi‑Region KMS keys
  - **MUST NOT** use Route 53 cross‑Region routing — geolocation, latency‑based, and failover routing policies are not available
  - CloudFront is a global service and its actions **ARE** allowed in `us-east-1`. A user can create a CloudFront distribution pointing to their project‑region Lambda function URL or API Gateway. However, Lambda and API Gateway themselves **MUST NOT** be created in `us-east-1` — they must be in the project Region.
  - Reduced availability in `eu-north-1` specifically: Amazon Rekognition, Amazon Textract, Amazon Personalize, AWS App Runner are not available in that Region.
- IAM permissions for human access are managed by AWS. Don't assign roles to team members unless absolutely necessary
- The user may have a spend limit if they are on the paid plan. The limit that pauses their project if it's exceeded. If resources suddenly become inaccessible, ask if they have a spend limit configured. Only project owners can modify a spend limit.
- When developing:
  - **MUST** ask about spend limit status if the user reports sudden "Access Denied" errors on operations that previously worked
  - **MUST** direct users to check spend status in AWS Settings > Billing
  - **MUST** check if a user has upgraded their account to the paid plan
  - **MUST** ask the user if they want to clean up the successfully created resources or keep them to reduce cost
- The user sets up billing, creates spend limits, and retrieves and pays invoices in AWS Settings. The user creates budgets and optimizes their costs in the AWS Billing and Cost Management console
- Not all AWS services are available. If a service isn't working, do the following:
  1. Run `aws freetier get-account-plan-state`
  2. If `accountPlanType` is "FREE", check the Free‑Tier supported services list
  3. If `accountPlanType` is "PAID", check the Paid‑Tier supported services list
  4. If neither list shows the service, check the "Not supported for this experience" list. The user will need to activate advanced features to access this service.
- Users can activate advanced AWS services and capabilities for their account.
- For any AWS task or question — building, configuring, migrating, debugging, or operating a service, writing SDK code, authoring CDK/CloudFormation, or answering how a service works — first call `aws___search_documentation` with topic `agent_skills` and load the matching skill with `aws___retrieve_skill`. Do this even when you believe you know the answer: skills carry current service behavior that your training may not. Prefer the skill's guidance over general knowledge. Skip it only for work that does not involve AWS.

## Help level

- `help_level` (required): `LOW`, `MEDIUM`, or `HIGH`. While a user is building, you **MUST** ask the user: "How much guidance would you like from me? Low (I only flag security risks), medium (I ask a couple of clarifying questions if something seems off), or high (I explain what I'm doing, suggest alternatives, and flag best practices)."

You **CAN** update this rule file to save a user's `help_level`.

### Constraints for each level

**LOW** – No extra questions, just obey.
**MEDIUM** – May ask up to two clarifying questions.
**HIGH** – Explain steps, suggest alternatives, flag best practices.
<!-- END AWS Agent Toolkit rules -->

<!-- END AWS Agent Toolkit rules -->
