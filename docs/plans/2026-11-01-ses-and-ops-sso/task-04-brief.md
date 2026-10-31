# Task 04 — IAM: allow `ses:SendEmail` for the control plane

**Where this fits:** the EC2 instance role `lanyard-ec2-ssm` has a permissions boundary
(`lanyard-ec2-ssm-runtime-boundary-v1`) that enumerates allowed actions. Without a new
boundary version **and** an identity policy statement, `ses:SendEmail` is denied even
though the SDK call is correct. This task is config + runbook only; no Go changes.

**Depends on:** nothing.
**Blocks:** 15 (the runbook link).

## Files

- `infra/iam/lanyard-ec2-ssm-runtime-boundary.json` (edit — append one statement)
- `infra/iam/lanyard-ses-send-policy.json` (create — role inline policy document)
- `infra/iam/README.md` (create — exact apply/verify commands)

## Statement to add (identical in both documents)

```json
{
  "Sid": "AllowSESSendEmail",
  "Effect": "Allow",
  "Action": ["ses:SendEmail"],
  "Resource": "arn:aws:ses:ap-southeast-2:459321894716:identity/linkedqueue.cloud"
}
```

Account `459321894716` and region `ap-southeast-2` come from the existing boundary file —
do not invent new values. Append the statement as the **last** element of `Statement` in
`lanyard-ec2-ssm-runtime-boundary.json`; leave every existing statement byte-identical.

`infra/iam/lanyard-ses-send-policy.json`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowSESSendEmail",
      "Effect": "Allow",
      "Action": ["ses:SendEmail"],
      "Resource": "arn:aws:ses:ap-southeast-2:459321894716:identity/linkedqueue.cloud"
    }
  ]
}
```

## `infra/iam/README.md` — content

```markdown
# IAM artefacts for the Lanyard single-host deployment

These files are the source of truth for the EC2 instance role `lanyard-ec2-ssm` and its
permissions boundary. Apply them with the `laneyard` AWS profile; they are not applied by
CI.

## SES login-code delivery

`ses:SendEmail` must appear in **both** the role's identity policy and the permissions
boundary, otherwise the call is denied.

1. Confirm the boundary ARN actually attached to the role (expected
   `arn:aws:iam::459321894716:policy/lanyard-ec2-ssm-runtime-boundary-v1`):

   ```sh
   aws iam get-role --profile laneyard --role-name lanyard-ec2-ssm \
     --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text
   ```

2. Add the identity policy:

   ```sh
   aws iam put-role-policy --profile laneyard --role-name lanyard-ec2-ssm \
     --policy-name lanyard-ses-send \
     --policy-document file://infra/iam/lanyard-ses-send-policy.json
   ```

3. Publish a new boundary version and make it the default. IAM keeps at most five
   versions; if the call fails with `LimitExceeded`, delete the oldest non-default
   version first (`aws iam list-policy-versions`).

   ```sh
   BOUNDARY_ARN="$(aws iam get-role --profile laneyard --role-name lanyard-ec2-ssm \
     --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text)"
   aws iam create-policy-version --profile laneyard --policy-arn "$BOUNDARY_ARN" \
     --policy-document file://infra/iam/lanyard-ec2-ssm-runtime-boundary.json \
     --set-as-default
   ```

4. Verify the effective documents:

   ```sh
   aws iam get-role-policy --profile laneyard --role-name lanyard-ec2-ssm \
     --policy-name lanyard-ses-send \
     --query 'PolicyDocument.Statement[0]'
   BOUNDARY_ARN="$(aws iam get-role --profile laneyard --role-name lanyard-ec2-ssm \
     --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text)"
   VERSION="$(aws iam get-policy --profile laneyard --policy-arn "$BOUNDARY_ARN" \
     --query Policy.DefaultVersionId --output text)"
   aws iam get-policy-version --profile laneyard --policy-arn "$BOUNDARY_ARN" \
     --version-id "$VERSION" --query 'PolicyVersion.Document.Statement[?Sid==`AllowSESSendEmail`]'
   ```

5. Confirm the sending identity exists and is verified in the same Region:

   ```sh
   aws sesv2 get-email-identity --profile laneyard --region ap-southeast-2 \
     --email-identity linkedqueue.cloud
   ```

   If the account is still in the SES sandbox, recipient addresses must be verified too
   until production access is granted.
```

## Verification

```sh
python -c "import json;json.load(open('infra/iam/lanyard-ec2-ssm-runtime-boundary.json'));json.load(open('infra/iam/lanyard-ses-send-policy.json'));print('ok')"
git diff --stat infra/iam/
```

`git diff` must show only the appended statement plus the two new files. Then run the
read-back commands from `infra/iam/README.md` and confirm `AllowSESSendEmail` is present in
both the identity policy and the default boundary version.
