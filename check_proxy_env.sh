echo "--- Proxy environment ---"
echo "TOKEN_KEY_ID=${TOKEN_KEY_ID}"
echo "TOKEN_ISSUER=${TOKEN_ISSUER}"
echo "TOKEN_AUDIENCE=${TOKEN_AUDIENCE}"
echo "TOKEN_PUBLIC_KEY=${TOKEN_PUBLIC_KEY}"
echo "UPSTREAM_URL=${UPSTREAM_URL}"
echo "ALLOW_INSECURE_DEMO=${ALLOW_INSECURE_DEMO}"
echo "--- Proxy inspect ---"
docker inspect lanyard-proxy-1 --format 'TOKEN_KEY_ID={{ .Config.Env.TOKEN_KEY_ID }}'
docker inspect lanyard-proxy-1 --format 'TOKEN_ISSUER={{ .Config.Env.TOKEN_ISSUER }}'
docker inspect lanyard-proxy-1 --format 'TOKEN_AUDIENCE={{ .Config.Env.TOKEN_AUDIENCE }}'
docker inspect lanyard-proxy-1 --format 'TOKEN_PUBLIC_KEY={{ .Config.Env.TOKEN_PUBLIC_KEY }}'
docker inspect lanyard-proxy-1 --format 'UPSTREAM_URL={{ .Config.Env.UPSTREAM_URL }}'
docker inspect lanyard-proxy-1 --format 'ALLOW_INSECURE_DEMO={{ .Config.Env.ALLOW_INSECURE_DEMO }}'
