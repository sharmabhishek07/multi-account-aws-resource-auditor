# GitHub OIDC → AWS IAM: Step-by-Step Setup

These steps create a role in your **management account** that GitHub Actions can assume via **OIDC**. That role will then assume the **per-member auditor role** in each account, and upload the HTML report to S3.

> Replace placeholders like `<ACCOUNT_ID>`, `<your-username>`, `<repo-name>`, and bucket names with your values.

---

## 1) Create (or verify) the GitHub OIDC Provider in AWS
1. Go to **IAM → Identity providers → Add provider**.
2. **Provider type:** OpenID Connect  
   **Provider URL:** `https://token.actions.githubusercontent.com`  
   **Audience:** `sts.amazonaws.com`
3. Save. (Only one OIDC provider is needed per AWS account.)

## 2) Create the GitHub OIDC Role in Management Account
1. Go to **IAM → Roles → Create role**.
2. **Trusted entity type:** Web identity  
   **Identity provider:** the provider from Step 1  
   **Audience:** `sts.amazonaws.com`
3. Name the role, e.g., **`GithubAuditRunnerRole`**.

### Trust Policy (restrict to your repo/branch)
Use this as the role's **trust policy** (Policy editor → JSON). It allows only your repo's `main` branch:
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::<ACCOUNT_ID>:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:<your-username>/<repo-name>:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

> To allow multiple branches, replace the exact `sub` match with a set like:  
> `"ForAnyValue:StringLike": { "token.actions.githubusercontent.com:sub": [ "repo:<your-username>/<repo-name>:ref:refs/heads/*" ] }`

### Inline Permissions Policy for the Management Role
Attach a policy that lets the role:
- Assume the **member-account** auditor role (e.g., `OrganizationAccountAccessRole`)
- Upload the HTML report to S3
- Optionally list AWS Organizations accounts (so you don't have to hardcode them)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeMemberAuditorRole",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
    },
    {
      "Sid": "UploadFindingsToS3",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl"
      ],
      "Resource": "arn:aws:s3:::<YOUR_S3_BUCKET>/findings/*"
    },
    {
      "Sid": "ListAccounts",
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts",
        "organizations:ListAccountsForParent"
      ],
      "Resource": "*"
    }
  ]
}
```

> If you prefer least-privilege, enumerate exact member account IDs instead of `*` in the `Resource` of `sts:AssumeRole`.

## 3) Configure GitHub Repository Variables
In **GitHub → Repo → Settings → Secrets and variables → Actions → Variables** add:
- `AWS_ROLE_TO_ASSUME` = ARN of the management role you created (e.g., `arn:aws:iam::<ACCOUNT_ID>:role/GithubAuditRunnerRole`)
- `S3_BUCKET` = your report bucket (e.g., `my-audit-reports-bucket`)
- **Optional** `AWS_REGION` = default region for the workflow (e.g., `ap-south-1`)

## 4) Verify the Workflow
The provided workflow file is at `.github/workflows/scheduled-audit.yml`. It:
- Configures credentials via OIDC
- Runs the auditor
- Uploads `out/findings.html` to `s3://$S3_BUCKET/findings/latest/findings.html`

Run it via **Actions → Scheduled Audit (OIDC) → Run workflow**. Check the job logs and confirm the HTML exists in your S3 bucket.

---

## Troubleshooting
- **AccessDenied on AssumeRole:** Ensure the member accounts have an **`OrganizationAccountAccessRole`** (or your chosen role) and its trust policy allows your management role to assume it.
- **S3 upload fails:** Confirm bucket name and the IAM policy includes `s3:PutObject` (and `s3:PutObjectAcl` if the bucket requires ACLs).
- **OIDC trust mismatch:** Make sure the `sub` matches your repo and branch exactly.
