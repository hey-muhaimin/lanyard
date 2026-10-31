#!/bin/bash
set -euo pipefail
HOST=database-1.c322g2se4k1x.ap-southeast-2.rds.amazonaws.com
TENANT=$(grep -m1 'TENANT_ID:' /opt/lanyard/production.compose.yml | sed 's/.*TENANT_ID: *"//; s/".*//')
DB=$(aws secretsmanager get-secret-value --secret-id production/lanyard/database --region ap-southeast-2 --query SecretString --output text)
U=$(echo "$DB" | jq -r .username)
P=$(echo "$DB" | jq -r .password)

echo "--- secrets rows as tenant $TENANT (app role) ---"
docker run --rm -e PGPASSWORD="$P" postgres:16-alpine psql -h "$HOST" -U "$U" -d lanyard -tA \
  -c "SET app.tenant_id = '$TENANT'; SELECT connector_id::text || ' | ' || secret_id || ' | ' || status FROM secrets"
echo "--- connectors ---"
docker run --rm -e PGPASSWORD="$P" postgres:16-alpine psql -h "$HOST" -U "$U" -d lanyard -tA \
  -c "SET app.tenant_id = '$TENANT'; SELECT id::text || ' | ' || coalesce(name,'') || ' | ' || kind FROM connectors"
echo "--- tenants ---"
docker run --rm -e PGPASSWORD="$P" postgres:16-alpine psql -h "$HOST" -U "$U" -d lanyard -tA \
  -c "SET app.tenant_id = '$TENANT'; SELECT id::text || ' | ' || name FROM tenants"
echo "--- leftover secret files on host ---"
ls -la /opt/lanyard/ | grep -E 'db-app|\.env' || echo "none"
