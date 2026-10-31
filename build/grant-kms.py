import json, subprocess, sys, os

key_arn = os.environ["KEY_ARN"]
tmp = "C:/Users/muhai/AppData/Local/Temp/opencode"

stmt = {
    "Sid": "LanyardVaultKMS",
    "Effect": "Allow",
    "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:DescribeKey",
    ],
    "Resource": key_arn,
}

# 1. identity inline policy
ident = {"Version": "2012-10-17", "Statement": [stmt]}
p1 = f"{tmp}/identity-kms.json"
open(p1, "w").write(json.dumps(ident))
subprocess.run(
    ["aws", "iam", "put-role-policy", "--profile", "laneyard", "--role-name", "lanyard-ec2-ssm",
     "--policy-name", "lanyard-vault-kms", "--policy-document", f"file://{p1}"],
    check=True,
)
print("identity policy: lanyard-vault-kms attached")

# 2. boundary: append statement, keep existing
boundary_arn = "arn:aws:iam::459321894716:policy/lanyard-ec2-ssm-production-boundary"
out = subprocess.run(
    ["aws", "iam", "get-policy", "--profile", "laneyard", "--policy-arn", boundary_arn,
     "--query", "Policy.DefaultVersionId", "--output", "text"],
    check=True, capture_output=True, text=True,
).stdout.strip()
doc = json.loads(subprocess.run(
    ["aws", "iam", "get-policy-version", "--profile", "laneyard", "--policy-arn", boundary_arn,
     "--version-id", out, "--query", "PolicyVersion.Document", "--output", "json"],
    check=True, capture_output=True, text=True,
).stdout)
existing = doc.get("Statement", [])
existing = [s for s in existing if s.get("Sid") != "LanyardVaultKMS"]
doc["Statement"] = existing + [stmt]
p2 = f"{tmp}/boundary-kms.json"
open(p2, "w").write(json.dumps(doc))
print("boundary statements:", len(doc["Statement"]))
subprocess.run(
    ["aws", "iam", "create-policy-version", "--profile", "laneyard", "--policy-arn", boundary_arn,
     "--policy-document", f"file://{p2}", "--set-as-default"],
    check=True,
)
print("boundary: new version set as default")
