import re

with open("/opt/lanyard/production.compose.yml", "r") as f:
    content = f.read()

# Replace with actual secret ARNs
content = content.replace("$DATABASE_SECRET_ARN", "arn:aws:secretsmanager:ap-southeast-2:459321894716:secret:production/lanyard/database-dHPHJS")
content = content.replace("$TOKEN_PRIVATE_KEY_SECRET_ARN", "arn:aws:secretsmanager:ap-southeast-2:459321894716:secret:production/lanyard/token-private-key-eMrS3S")
content = content.replace("$TOKEN_PUBLIC_KEY_SECRET_ARN", "arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/token-public-key-2FL5or")
content = content.replace("$UPSTREAM_SECRET_ARN", "arn:aws:secretsmanager:ap-southeast-2:459321894716:secret/production/lanyard/upstream-credential-27MfbI")
content = content.replace("$TOKEN_KEY_ID", "lanyard-production-20261031-1")
content = content.replace("$TOKEN_ISSUER", "lanyard")
content = content.replace("$TOKEN_AUDIENCE", "lanyard")
content = content.replace("$UPSTREAM_URL", "https://example.com")

# Add ALLOW_INSECURE_DEMO to proxy environment
content = content.replace("      PROXY_CONNECTOR_ID:    1325PROXY_CONNECTOR_ID\n", "      PROXY_CONNECTOR_ID: demo-connector\n      ALLOW_INSECURE_DEMO: \"true\"\n")

with open("/opt/lanyard/production.compose.yml", "w") as f:
    f.write(content)
print("Updated compose file")
