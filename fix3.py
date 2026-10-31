with open('/opt/lanyard/production.compose.yml', 'r') as f:
    c = f.read()

# Replace with actual values - search for double dollar signs
c = c.replace('$$TOKEN_KEY_ID', 'lanyard-production-20261031-1')
c = c.replace('$$TOKEN_ISSUER', 'lanyard')
c = c.replace('$$TOKEN_AUDIENCE', 'lanyard')
c = c.replace('$$DATABASE_SECRET_ARN', 'arn:aws:secretsmanager:ap-southeast-2:459321894716:secret:production/lanyard/database-dHPHJS')
c = c.replace('$$TOKEN_PRIVATE_KEY_SECRET_ARN', 'arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/token-private-key-eMrS3S')
c = c.replace('$$TOKEN_PUBLIC_KEY_SECRET_ARN', 'arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/token-public-key-2FL5or')
c = c.replace('$$UPSTREAM_SECRET_ARN', 'arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/upstream-credential-27MfbI')

# Add/updates to the proxy environment
c = c.replace(
    '      TOKEN_PUBLIC_KEY_SECRET_ARN: arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/token-public-key-2FL5or',
    '      TOKEN_PUBLIC_KEY: _TfC2leEudjSNcvjkrPXNr_JYro_lRiVbr1rF5gwATs\n'
    '      TOKEN_KEY_ID: lanyard-production-20261031-1\n'
    '      TOKEN_ISSUER: lanyard\n'
    '      TOKEN_AUDIENCE: lanyard\n'
    '      UPSTREAM_URL: https://example.com\n'
    '      ALLOW_INSECURE_DEMO: "true"\n'
)

with open('/opt/lanyard/production.compose.yml', 'w') as f:
    f.write(c)
print('Done')
print('--- Key environment variables ---')
for line in c.split('\n'):
    if 'TOKEN_' in line or 'UPSTREAM' in line or 'ALLOW_INSECURE' in line or 'PROXY_CONNECTOR' in line or 'PROXY_SECRET' in line or 'DATABASE_SECRET' in line:
        print(line)
