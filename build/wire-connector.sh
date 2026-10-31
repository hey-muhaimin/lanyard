#!/bin/bash
set -euo pipefail
REGION=ap-southeast-2
HOST=database-1.c322g2se4k1x.ap-southeast-2.rds.amazonaws.com
DB=$(aws secretsmanager get-secret-value --secret-id production/lanyard/database --region $REGION --query SecretString --output text)
U=$(echo "$DB" | jq -r .username)
P=$(echo "$DB" | jq -r .password)
TENANT=$(grep -m1 'TENANT_ID:' /opt/lanyard/production.compose.yml | sed 's/.*TENANT_ID: *"//; s/".*//')

CONNECTOR_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
docker run --rm -e PGPASSWORD="$P" postgres:16-alpine psql -h "$HOST" -U "$U" -d lanyard -v ON_ERROR_STOP=1 -q \
  -c "SET app.tenant_id = '$TENANT'; INSERT INTO connectors (id, tenant_id, kind, allowed_hosts, config, name) VALUES ('$CONNECTOR_ID','$TENANT','http',ARRAY['api.github.com'],'{}'::jsonb,'github') ON CONFLICT (id) DO NOTHING"
echo "connector: $CONNECTOR_ID"

python3 - "$CONNECTOR_ID" <<'PY'
import sys
p = "/opt/lanyard/production.compose.yml"
cid = sys.argv[1]
lines = open(p).read().splitlines()
out = []
for l in lines:
    if l.strip().startswith("PROXY_CONNECTOR_ID:"):
        indent = l[: len(l) - len(l.lstrip())]
        out.append(f"{indent}PROXY_CONNECTOR_ID: {cid}")
    else:
        out.append(l)
open(p, "w").write("\n".join(out) + "\n")
print("compose connector set:", sum(1 for l in out if cid in l))
PY

cd /opt/lanyard && docker compose -f production.compose.yml up -d --force-recreate 2>&1 | tail -3
sleep 15
docker ps --format '{{.Names}} {{.Status}}'
echo -n "proxy /readyz: "; curl -s -w " %{http_code}\n" http://127.0.0.1:8081/readyz
echo "--- proxy logs ---"; docker logs --tail 4 lanyard-proxy-1 2>&1
