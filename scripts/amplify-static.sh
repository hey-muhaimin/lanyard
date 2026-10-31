#!/usr/bin/env bash
# Redeploy / roll back the Lanyard static UIs on AWS Amplify Hosting.
#
# The console and ops UIs are Next.js static exports (`npm run build:static`).
# They are published to Amplify with manual zip deployments, so no Git
# connection, no build minutes, and no ALB/DNS involvement.
#
# Usage:
#   ./scripts/amplify-static.sh status
#   ./scripts/amplify-static.sh deploy console            # build + publish
#   ./scripts/amplify-static.sh deploy ops --skip-build   # publish existing out/
#   ./scripts/amplify-static.sh rollback ops              # delete app (asks first)
#
# Environment:
#   AWS_PROFILE  AWS profile to use (default: laneyard)
#   AWS_REGION   Region containing the Amplify apps (default: ap-southeast-2)
set -euo pipefail

PROFILE="${AWS_PROFILE:-laneyard}"
REGION="${AWS_REGION:-ap-southeast-2}"
BRANCH="main"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TMP_DIR="${TMPDIR:-/tmp}"

app_id() {
  case "$1" in
    console) echo "d1lcbkfzsvmcpm" ;;
    ops)     echo "d1jn78ivrwzwfr" ;;
    *) echo "unknown app: $1 (expected: console|ops)" >&2; return 1 ;;
  esac
}

app_dir() {
  case "$1" in
    console) echo "$ROOT/web/console" ;;
    ops)     echo "$ROOT/web/ops" ;;
  esac
}

aws_cli() {
  aws --profile "$PROFILE" --region "$REGION" "$@"
}

json_field() {
  python -c "import sys,json;print(json.load(sys.stdin)['$1'])"
}

cmd_status() {
  for APP in console ops; do
    ID="$(app_id "$APP")"
    echo "== $APP ($ID) =="
    aws_cli amplify get-app --app-id "$ID" \
      --query 'app.[name,defaultDomain,platform]' --output text
    aws_cli amplify list-jobs --app-id "$ID" --branch-name "$BRANCH" \
      --query 'jobSummaries[0:3].[jobId,status,startTime]' --output text
  done
}

# Amplify refuses a new deployment while an earlier job is unfinished. Stale
# pending jobs accumulate whenever a zip upload is abandoned, so clear them.
clear_pending_jobs() {
  local id="$1"
  local jobs
  jobs="$(aws_cli amplify list-jobs --app-id "$id" --branch-name "$BRANCH" \
    --query "jobSummaries[?status=='PENDING'].jobId" --output text 2>/dev/null || true)"
  for JOB in $jobs; do
    echo "  cancelling stale pending job $JOB"
    aws_cli amplify stop-job --app-id "$id" --branch-name "$BRANCH" --job-id "$JOB" >/dev/null 2>&1 || true
  done
}

cmd_deploy() {
  local app="$1"; shift || true
  local skip_build=0
  for arg in "$@"; do
    [[ "$arg" == "--skip-build" ]] && skip_build=1
  done

  local id dir out zip
  id="$(app_id "$app")"
  dir="$(app_dir "$app")"
  out="$dir/out"
  zip="$TMP_DIR/lanyard-$app-out.zip"

  if [[ "$skip_build" -eq 0 ]]; then
    echo "== building $app (npm run build:static) =="
    npm --prefix "$dir" run build:static
  else
    echo "== skipping build, publishing existing $out =="
  fi

  [[ -f "$out/index.html" ]] || { echo "missing $out/index.html" >&2; exit 1; }

  echo "== packaging $out =="
  python - "$out" "$zip" <<'PY'
import os, sys, zipfile
src, dst = sys.argv[1], sys.argv[2]
with zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as z:
    for root, _dirs, files in os.walk(src):
        for name in files:
            path = os.path.join(root, name)
            arc = os.path.relpath(path, src).replace(os.sep, "/")
            z.write(path, arc)
print(f"  {dst} ({os.path.getsize(dst)} bytes)")
PY

  clear_pending_jobs "$id"

  echo "== creating deployment for $app ($id/$BRANCH) =="
  local dep job url
  dep="$(aws_cli amplify create-deployment --app-id "$id" --branch-name "$BRANCH" --output json)"
  job="$(echo "$dep" | json_field jobId)"
  url="$(echo "$dep" | json_field zipUploadUrl)"

  echo "  uploading zip (job $job)"
  curl -sS -X PUT --upload-file "$zip" "$url" -o /dev/null

  aws_cli amplify start-deployment --app-id "$id" --branch-name "$BRANCH" \
    --job-id "$job" --query 'jobSummary.[jobId,status]' --output text

  echo "== waiting for job $job =="
  local status=""
  for _ in $(seq 1 60); do
    sleep 5
    status="$(aws_cli amplify get-job --app-id "$id" --branch-name "$BRANCH" \
      --job-id "$job" --query 'job.summary.status' --output text)"
    case "$status" in
      SUCCEED|FAILED|CANCELLED) break ;;
    esac
  done
  echo "  job $job: $status"
  [[ "$status" == "SUCCEED" ]] || { echo "deployment did not succeed" >&2; exit 1; }

  echo "  live: https://$BRANCH.$id.amplifyapp.com/"
}

# Resolve via Google Public DNS: the local resolver on some networks mangles
# CloudFront answers, and Amplify hostnames are edge-cached CNAMEs.
dns_query() {
  curl -s -m 20 -H 'accept: application/dns-json' \
    "https://dns.google/resolve?name=$1&type=$2" |
    python -c "import sys,json;d=json.load(sys.stdin);a=d.get('Answer');print(d.get('Status'),[r['data'] for r in a] if a else 'NOANSWER')" 2>/dev/null ||
    echo "query-failed"
}

cmd_verify() {
  local cert="arn:aws:acm:us-east-1:459321894716:certificate/6fc2607a-5247-4ed0-9edc-b09067e6a3ff"
  echo "== certificate (us-east-1, required for Amplify custom domains) =="
  aws --profile "$PROFILE" --region us-east-1 acm describe-certificate \
    --certificate-arn "$cert" --query 'Certificate.[Status,DomainName]' --output text

  for APP in console ops; do
    local id
    id="$(app_id "$APP")"
    echo
    echo "== $APP =="
    aws_cli amplify get-domain-association --app-id "$id" --domain-name linkedqueue.cloud \
      --query 'domainAssociation.[domainStatus,subDomains[0].verified,subDomains[0].dnsRecord]' \
      --output text 2>/dev/null || echo "  no domain association"
    printf '  dns %-28s ' "$APP.linkedqueue.cloud"
    dns_query "$APP.linkedqueue.cloud" CNAME
    printf '  http %-27s ' "https://$APP.linkedqueue.cloud/"
    curl -s -m 25 -o /dev/null -w '%{http_code}\n' "https://$APP.linkedqueue.cloud/" 2>/dev/null || echo "unreachable"
  done

  echo
  echo "== apex redirect =="
  printf '  dns %-28s ' "linkedqueue.cloud"
  dns_query linkedqueue.cloud A
  printf '  http %-27s ' "https://linkedqueue.cloud/"
  curl -s -m 25 -o /dev/null -D - "https://linkedqueue.cloud/" 2>/dev/null |
    grep -Ei '^(HTTP/|location:)' | tr -d '\r' | paste -sd' ' -
}

cmd_rollback() {
  local app="$1"
  local id
  id="$(app_id "$app")"
  echo "This deletes the $app Amplify app ($id) and its URL."
  echo "No other infrastructure (ALB, EC2, RDS, S3 deploy bucket) is touched."
  read -r -p "Type the app id to confirm: " confirm
  [[ "$confirm" == "$id" ]] || { echo "aborted"; exit 1; }
  aws_cli amplify delete-app --app-id "$id"
  echo "deleted $app ($id)"
}

case "${1:-}" in
  status)   cmd_status ;;
  verify)   cmd_verify ;;
  deploy)   shift; cmd_deploy "${1:?app required: console|ops}" "${@:2}" ;;
  rollback) shift; cmd_rollback "${1:?app required: console|ops}" ;;
  *)
    echo "usage: $0 {status|deploy <console|ops> [--skip-build]|rollback <console|ops>}" >&2
    exit 1
    ;;
esac
