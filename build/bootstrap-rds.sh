#!/bin/bash
set -euo pipefail
REGION=ap-southeast-2
RDS_HOST=database-1.c322g2se4k1x.ap-southeast-2.rds.amazonaws.com
DB_NAME=lanyard
IMAGE=lanyard-production-20261031-4
DB_SECRET=production/lanyard/database
PUB_KEY_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id production/lanyard/token-public-key --region $REGION --query ARN --output text)
PRIV_KEY_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id production/lanyard/token-private-key --region $REGION --query ARN --output text)
UPSTREAM_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id production/lanyard/upstream-credential --region $REGION --query ARN --output text)
DB_SECRET_ARN=$(aws secretsmanager describe-secret --secret-id "$DB_SECRET" --region $REGION --query ARN --output text)

psql_run() {
  docker run --rm -e PGPASSWORD="$MASTER_PASS" postgres:16-alpine \
    psql -h "$RDS_HOST" -U "$MASTER_USER" -d "$1" -v ON_ERROR_STOP=1 -tAc "$2"
}

DB_JSON=$(aws secretsmanager get-secret-value --secret-id "$DB_SECRET" --region $REGION --query SecretString --output text)
MASTER_USER=$(echo "$DB_JSON" | jq -r .username)
MASTER_PASS=$(echo "$DB_JSON" | jq -r .password)
echo "bootstrap user: $MASTER_USER"

# 1. database
if [ "$(psql_run postgres "SELECT 1 FROM pg_database WHERE datname='$DB_NAME'")" != "1" ]; then
  psql_run postgres "CREATE DATABASE $DB_NAME"
  echo "created database $DB_NAME"
else
  echo "database $DB_NAME already exists"
fi

# 2. migrations (as master, TLS required)
ENC_PASS=$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$MASTER_PASS")
MIGRATE_URL="postgres://$MASTER_USER:$ENC_PASS@$RDS_HOST:5432/$DB_NAME?sslmode=require"
docker run --rm -e DATABASE_URL="$MIGRATE_URL" --entrypoint /app/migrate "$IMAGE"

# 3. tenant
TENANT_ID=$(python3 -c "import uuid;print(uuid.uuid4())")
psql_run "$DB_NAME" "INSERT INTO tenants (id,name) VALUES ('$TENANT_ID','Lanyard Production') ON CONFLICT (id) DO NOTHING" >/dev/null
echo "tenant: $TENANT_ID"

# 4. app role password
APP_PASS=$(openssl rand -hex 24)
psql_run "$DB_NAME" "ALTER ROLE lanyard_app PASSWORD '$APP_PASS'" >/dev/null
APP_JSON=$(jq -n --arg h "$RDS_HOST" --arg u lanyard_app --arg p "$APP_PASS" --arg d "$DB_NAME" \
  '{engine:"postgres",host:$h,port:5432,username:$u,password:$p,dbname:$d,sslmode:"require"}')

DB_MODE="secret"
if aws secretsmanager put-secret-value --secret-id "$DB_SECRET" --secret-string "$APP_JSON" --region $REGION >/dev/null 2>&1; then
  echo "rotated $DB_SECRET to lanyard_app credentials"
else
  DB_MODE="env"
  umask 077
  APP_URL="postgres://lanyard_app:$(python3 -c "import urllib.parse,sys;print(urllib.parse.quote(sys.argv[1],safe=''))" "$APP_PASS")@$RDS_HOST:5432/$DB_NAME?sslmode=require"
  printf 'DATABASE_URL=%s\n' "$APP_URL" > /opt/lanyard/db-app.env
  echo "put-secret-value denied; wrote /opt/lanyard/db-app.env (0600) instead"
fi

if [ "$DB_MODE" = "secret" ]; then
  DB_ENV="      DATABASE_SECRET_ARN: $DB_SECRET_ARN"
  DB_EXTRA=""
else
  DB_ENV=""
  DB_EXTRA="    env_file:
      - /opt/lanyard/db-app.env"
fi

cat > /opt/lanyard/production.compose.yml <<COMPOSE
name: lanyard
services:
  controlplane:
    image: $IMAGE
    pull_policy: never
    command: ["/app/controlplane"]
    restart: unless-stopped
    init: true
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    stop_grace_period: 15s
$DB_EXTRA
    ports:
      - "127.0.0.1:8080:8080"
    environment:
      PORT: "8080"
      LOG_LEVEL: info
      TENANT_ID: "$TENANT_ID"
      AWS_REGION: $REGION
      KMS_KEY_ID: alias/lanyard-production-storage
      VAULT_KEY_ID: alias/lanyard-production-storage
$DB_ENV
      TOKEN_PRIVATE_KEY_SECRET_ARN: $PRIV_KEY_SECRET_ARN
      TOKEN_KEY_ID: $IMAGE
      TOKEN_ISSUER: lanyard
      TOKEN_AUDIENCE: lanyard
  proxy:
    image: $IMAGE
    pull_policy: never
    command: ["/app/proxy"]
    restart: unless-stopped
    init: true
    read_only: true
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    stop_grace_period: 15s
$DB_EXTRA
    ports:
      - "127.0.0.1:8081:8081"
    environment:
      PORT: "8081"
      LOG_LEVEL: info
      TENANT_ID: "$TENANT_ID"
      AWS_REGION: $REGION
      KMS_KEY_ID: alias/lanyard-production-storage
      VAULT_KEY_ID: alias/lanyard-production-storage
$DB_ENV
      UPSTREAM_URL: https://api.github.com
      UPSTREAM_SECRET_ARN: $UPSTREAM_SECRET_ARN
      PROXY_CONNECTOR_ID: github
      PROXY_SECRET_ID: github-token
      TOKEN_KEY_ID: $IMAGE
      TOKEN_ISSUER: lanyard
      TOKEN_AUDIENCE: lanyard
      TOKEN_PUBLIC_KEY_SECRET_ARN: $PUB_KEY_SECRET_ARN
COMPOSE
echo "wrote /opt/lanyard/production.compose.yml (db mode: $DB_MODE)"

echo "--- migrations applied ---"
psql_run "$DB_NAME" "SELECT string_agg(version, ',' ORDER BY version) FROM schema_migrations"
echo "--- app role ---"
psql_run "$DB_NAME" "SELECT rolname||' bypassrls='||rolbypassrls||' login='||rolcanlogin FROM pg_roles WHERE rolname='lanyard_app'"
echo "--- rls tables ---"
psql_run "$DB_NAME" "SELECT count(*) FROM pg_tables WHERE schemaname='public' AND rowsecurity"
