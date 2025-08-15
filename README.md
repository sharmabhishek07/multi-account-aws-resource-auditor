
<p align="center">
  <a href="https://github.com/<your-username>/multi-account-aws-resource-auditor/actions/workflows/scheduled-audit.yml">
    <img src="https://github.com/<your-username>/multi-account-aws-resource-auditor/actions/workflows/scheduled-audit.yml/badge.svg?branch=main" alt="Scheduled Audit status" />
  </a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="#"><img src="https://img.shields.io/badge/Python-3.11%2B-informational.svg" alt="Python 3.11+"></a>
</p>

# Multi-Account AWS Resource Auditor

Audits multiple AWS accounts (via AWS Organizations + STS AssumeRole) and produces CSV + HTML reports of potential cost, security, and hygiene issues:
- **EC2**: stopped instances older than threshold; AMIs without recent use.
- **EBS**: unattached volumes; snapshots without recent use.
- **S3**: public buckets; buckets missing encryption or versioning.
- **Lambda**: functions with no invocations in the last N days; untagged functions.
- **RDS**: stopped or storage-not-optimized instances; snapshots without encryption.

## Why this project?
- Demonstrates **multi-account automation** with `boto3` and cross-account role assumption.
- Clean, testable Python package with CLI.
- CI includes linting, unit tests, and security checks.

## Quick Start (Local CLI)

1. **Install** (Python 3.11+ recommended):
   ```bash
   pip install -r requirements.txt
   ```

2. **AWS Credentials**: Configure credentials for the **management (payer) account** that can call Organizations (or provide a static `accounts` list in `config.yaml`).

3. **Config**: Copy and edit the sample config:
   ```bash
   cp sample_config.yaml config.yaml
   ```

4. **Run audit**:
   ```bash
   python -m auditor --config config.yaml
   ```

5. **Outputs** (in `./out/` by default):
   - `findings.csv`
   - `findings.html`

## Deployment as a (Optional) Scheduled Job
- You can run this as a weekly GitHub Actions workflow using OIDC + `aws-actions/configure-aws-credentials` (example provided in `.github/workflows/ci.yml`), or on an EC2/Lambda/Container scheduled via EventBridge.
- Terraform template in `terraform/` shows how to create an **AuditorRole** in each member account and trust the management account or your CI's OIDC provider.

## Configuration (`config.yaml`)

```yaml
# role to assume in each member account (must exist there with needed read-only permissions)
assume_role_name: OrganizationAccountAccessRole
external_id: ""  # optional

# regions to scan (omit to auto-discover recommended regions)
regions: ["us-east-1", "us-west-2", "ap-south-1"]

# exclude certain account IDs
exclude_accounts: []

# thresholds (days)
stale_days:
  lambda_no_invocations: 30
  ec2_stopped_older_than: 7

# output directory
output_dir: "./out"

# optional: hardcode accounts if you don't have Organizations permissions
# accounts:
#   - id: "111111111111"
#     name: "dev"
#   - id: "222222222222"
#     name: "prod"
```

## Permissions

In each **member account**, attach a role named `OrganizationAccountAccessRole` (or your chosen `assume_role_name`) with **read-only** policies for EC2, EBS, S3, Lambda, RDS (and any additional services you enable). The management account (or CI OIDC principal) must be allowed to assume that role.

## Services & Checks

- **EC2**
  - Stopped instances older than `stale_days.ec2_stopped_older_than`
- **EBS**
  - Unattached volumes
- **S3**
  - Buckets with public ACL or policy
  - Buckets missing **default encryption** or **versioning**
- **Lambda**
  - Functions with no invocations within `stale_days.lambda_no_invocations` days
  - Untagged functions
- **RDS**
  - Snapshots without encryption

> Findings are tagged with `severity` (LOW/MEDIUM/HIGH) and include a suggested remediation line.

## CLI

```bash
python -m auditor --config config.yaml --only s3,ec2 --out ./out
```

## Dev Notes

- Python package in `src/auditor`
- Minimal unit tests in `tests/`
- CI: `ruff`, `pytest`, `bandit`, `pip-audit`

## License
MIT


---

## Docker (Containerized Run)

Build:
```bash
docker build -t aws-resource-auditor .
```

Run (mount a local config and write outputs to ./out):
```bash
docker run --rm -v $(pwd)/config.yaml:/app/config.yaml -v $(pwd)/out:/app/out aws-resource-auditor   python -m auditor --config config.yaml --only s3,ec2,iam
```

> Provide credentials via your environment or docker's `-e` flags (e.g., `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_REGION`) or use an IRSA/role when running in AWS.

## Scheduled GitHub Actions with OIDC + S3 Upload

> **Step-by-step guide:** See [`docs/oidc-setup.md`](docs/oidc-setup.md)

The workflow `.github/workflows/scheduled-audit.yml` demonstrates:
- OIDC federation to assume an AWS role (`vars.AWS_ROLE_TO_ASSUME`)
- Scheduled weekly runs (cron) and manual dispatch
- Audit execution
- Uploading `findings.html` to an S3 bucket (`vars.S3_BUCKET`)

### Set up
1. Create an IAM role in your AWS account that trusts GitHub OIDC and allows assuming the auditing role in member accounts.
2. In your GitHub repo **Settings → Secrets and variables → Actions → Variables**, set:
   - `AWS_ROLE_TO_ASSUME` – The role ARN to assume in your management account
   - `S3_BUCKET` – The bucket to upload the HTML report to
   - Optionally `AWS_REGION` – default region for the workflow

3. (Optional) Adjust the cron in the workflow if you want a different schedule.

When it runs, the HTML report will be available at:
`s3://$S3_BUCKET/findings/latest/findings.html`

<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/cf6bfba4-90f1-4a7e-9975-24b530da4be2" />

