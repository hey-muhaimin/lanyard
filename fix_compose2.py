with open('/opt/lanyard/production.compose.yml', 'r') as f:
    c = f.read()

# Add/Update the required environment variables
# 1. Add TOKEN_PUBLIC_KEY with the actual key value
# 2. Add UPSTREAM_URL
# 3. Add ALLOW_INSECURE_DEMO

# Find the proxy environment section and add/update TOKEN_PUBLIC_KEY
c = c.replace(
    '      TOKEN_PUBLIC_KEY_SECRET_ARN: arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/token-public-key-2FL5or\n',
    '      TOKEN_PUBLIC_KEY: _TfC2leEudjSNcvjkrPXNr_JYro_lRiVbr1rF5gwATs\n'
)

# Add UPSTREAM_URL and ALLOW_INSECURE_DEMO
c = c.replace(
    '      TOKEN_AUDIENCE: lanyard\n',
    '      TOKEN_AUDIENCE: lanyard\n'
    '      UPSTREAM_URL: https://example.com\n'
    '      ALLOW_INSECURE_DEMO: \"true\"\n'
)

with open('/opt/lanyard/production.compose.yml', 'w') as f:
    f.write(c)
print('Done')
print('--- Key environment variables ---')
for line in c.split('\n'):
    if 'TOKEN_' in line or 'UPSTREAM' in line or 'ALLOW_INSECURE' in line or 'PROXY_CONNECTOR' in line or 'PROXY_SECRET' in line:
        print(line)
