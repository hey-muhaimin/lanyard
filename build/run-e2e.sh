#!/bin/bash
set -euo pipefail
HOST=database-1.c322g2se4k1x.ap-southeast-2.rds.amazonaws.com
TENANT=$(grep -m1 'TENANT_ID:' /opt/lanyard/production.compose.yml | sed 's/.*TENANT_ID: *"//; s/".*//')
CONNECTOR=$(grep -m1 'PROXY_CONNECTOR_ID:' /opt/lanyard/production.compose.yml | sed 's/.*PROXY_CONNECTOR_ID: *//')

chmod +x /tmp/e2e
PUB=$(/tmp/e2e keygen)
echo "agent_public_key=$PUB"

sed -i "s/__TENANT__/$TENANT/g; s|__PUBKEY__|$PUB|g" /tmp/setup-e2e.sql

DB=$(aws secretsmanager get-secret-value --secret-id production/lanyard/database --region ap-southeast-2 --query SecretString --output text)
U=$(echo "$DB" | jq -r .username)
P=$(echo "$DB" | jq -r .password)

docker run --rm -i -e PGPASSWORD="$P" -v /tmp:/sql:ro postgres:16-alpine \
  psql -h "$HOST" -U "$U" -d lanyard -v ON_ERROR_STOP=1 \
  -c "SET app.tenant_id = '$TENANT'" -f /sql/setup-e2e.sql

echo "--- agent + policy ---"
docker run --rm -e PGPASSWORD="$P" postgres:16-alpine psql -h "$HOST" -U "$U" -d lanyard -tA \
  -c "SET app.tenant_id = '$TENANT'; SELECT slug || ' | ' || status FROM agents"
docker run --rm -e PGPASSWORD="$P" postgres:16-alpine psql -h "$HOST" -U "$U" -d lanyard -tA \
  -c "SET app.tenant_id = '$TENANT'; SELECT version || ' | ' || status FROM policies"

echo "--- grant ---"
export E2E_ACTOR=e2e-agent E2E_CONNECTOR="$CONNECTOR" E2E_RESOURCE=github-token
/tmp/e2e grant
echo "--- proxy ---"
/tmp/e2e proxy
