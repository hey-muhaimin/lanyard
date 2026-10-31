#!/usr/bin/env bash
set -euo pipefail

# ----------------------------------------------------------------------
# 1️⃣  CONFIG – replace these values with yours if they differ
# ----------------------------------------------------------------------
export ACCOUNT_ID=459321894716          # your AWS account/project ID
export REGION=ap-southeast-2            # the *selected* region for this project
export PROJECT_NAME=lanyard             # logical project name used in ECR repo tags
export DOMAIN=linkedqueue.cloud          # the public hostname you own
export ALB_DNS_NAME=""                  # will be filled automatically after CDK deploy
export CF_DISTRIBUTION_DOMAIN=""        # will be filled automatically after CDK deploy

# ----------------------------------------------------------------------
# 2️⃣  Make sure you have the required tools
# ----------------------------------------------------------------------
command -v docker    >/dev/null  || { echo "❌ Docker not found – install it first"; exit 1; }
command -v aws      >/dev/null  || { echo "❌ AWS CLI not found – install it first"; exit 1; }
command -v npx      >/dev/null  || { echo "❌ npx (Node.js) not found – install Node.js 20+ first"; exit 1; }

# ----------------------------------------------------------------------
# 3️⃣  Log in to Amazon ECR
# ----------------------------------------------------------------------
echo "🔐 Logging in to ECR (${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com)…"
aws ecr get-login-password --region "${REGION}" |
  docker login --username AWS --password-stdin "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

# ----------------------------------------------------------------------
# 4️⃣  Build & push the **Console** image (port 3000)
# ----------------------------------------------------------------------
echo "🏗️  Building Console image…"
docker build -t "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}/console:latest" ./web/console

echo "📤 Pushing Console image…"
docker push "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}/console:latest"

# ----------------------------------------------------------------------
# 5️⃣  Build & push the **Ops** image (port 4000)
# ----------------------------------------------------------------------
echo "🏗️  Building Ops image…"
docker build -t "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}/ops:latest" ./web/ops

echo "📤 Pushing Ops image…"
docker push "${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/${PROJECT_NAME}/ops:latest"

# ----------------------------------------------------------------------
# 6️⃣  CDK – bootstrap (only needed once) and deploy the Lanyard stack
# ----------------------------------------------------------------------
echo "🚀 Bootstrapping CDK for the account/region (run once per account)…"
npx cdk bootstrap "aws://${ACCOUNT_ID}/${REGION}"

echo "📦 Deploying the Lanyard CDK stack…"
# The stack name is the class name from cdk/lib/lanyard-stack.ts
npx cdk deploy LanyardStack --require-approval never

# ----------------------------------------------------------------------
# 7️⃣  Capture CDK outputs (ECR repo URI, ALB DNS name, CloudFront domain)
# ----------------------------------------------------------------------
echo "🔎 Fetching CDK stack outputs…"
CF_DISTRIBUTION_DOMAIN=$(aws cloudformation describe-stacks \
  --stack-name LanyardStack \
  --region "${REGION}" \
  --query "Stacks[0].Outputs[?OutputKey=='DistributionDomain'].OutputValue" \
  --output text)

ALB_DNS_NAME=$(aws cloudformation describe-stacks \
  --stack-name LanyardStack \
  --region "${REGION}" \
  --query "Stacks[0].Outputs[?OutputKey=='LanyardLBDnsName'].OutputValue" \
  --output text || true)   # may be empty if the CDK stack doesn’t expose it

echo "✅ CloudFront domain  : ${CF_DISTRIBUTION_DOMAIN}"
if [[ -n "${ALB_DNS_NAME}" ]]; then
  echo "✅ ALB DNS name      : ${ALB_DNS_NAME}"
fi

# ----------------------------------------------------------------------
# 8️⃣  DNS – add a CNAME record for your public domain
# ----------------------------------------------------------------------
# NOTE: The exact commands depend on where you manage DNS. The repo uses Hostinger.
# Below are two options you can run manually in your Hostinger dashboard or via
# their API (if you have API credentials).

# ── Option A – point directly to the ALB (quick & simple) ─────────────────────
if [[ -n "${ALB_DNS_NAME}" ]]; then
  echo ""
  echo "🔧 DNS step (Option A – ALB):"
  echo "   In your Hostinger DNS zone, create a CNAME record:"
  echo "       Name: @   (or leave blank for the apex)"
  echo "       Target: ${ALB_DNS_NAME}"
  echo "   TTL: default (or 300 s)."
  echo "   Save the change and wait for propagation (usually < 5 min)."
fi

# ── Option B – point to CloudFront (recommended for TLS, caching, WAF) ───────
echo ""
echo "🔧 DNS step (Option B – CloudFront – recommended):"
echo "   In your Hostinger DNS zone, create a CNAME record:"
echo "       Name: @   (or leave blank for the apex)"
echo "       Target: ${CF_DISTRIBUTION_DOMAIN}"
echo "   TTL: default."
echo "   This routes traffic via the CloudFront distribution, which fronts the"
echo "   ALB for API routes and the S3 bucket for static assets."
echo ""
echo "📌 After the CNAME propagates, you can reach the UI at:"
echo "   https://${DOMAIN}             (Console UI – path / )"
echo "   https://${DOMAIN}/ops         (Ops UI – path /ops )"
echo ""
echo "🎉 All set! If you need to tweak anything (e.g., change desired task count,"
echo "   update environment variables, or add custom WAF rules), just modify the"
echo "   CDK code in \`cdk/lib/lanyard-stack.ts\` and run \`npx cdk deploy LanyardStack\` again."
