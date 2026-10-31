import os

p = "/opt/lanyard/production.compose.yml"
arn = open("/tmp/db_arn.txt").read().strip()
lines = open(p).read().splitlines()

out, skip = [], False
for l in lines:
    if l.strip() == "env_file:":
        skip = True
        continue
    if skip and l.strip() == "- /opt/lanyard/db-app.env":
        skip = False
        continue
    skip = False
    out.append(l)

res = []
for l in out:
    res.append(l)
    if "VAULT_KEY_ID: alias/lanyard-production-storage" in l:
        indent = l[: len(l) - len(l.lstrip())]
        res.append(f"{indent}DATABASE_SECRET_ARN: {arn}")

open(p, "w").write("\n".join(res) + "\n")
if os.path.exists("/opt/lanyard/db-app.env"):
    os.remove("/opt/lanyard/db-app.env")

print("env_file_blocks_left:", sum(1 for l in res if "env_file" in l))
print("db_secret_lines:", sum(1 for l in res if "DATABASE_SECRET_ARN" in l))
