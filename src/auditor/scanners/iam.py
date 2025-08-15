from __future__ import annotations
from datetime import datetime, timezone

def scan_iam(session, account_id: str, region: str, conf) -> list[dict]:
    # IAM is global; region parameter is unused but kept for uniformity
    findings = []
    iam = session.client("iam")

    max_age = conf.stale_days.iam_key_max_age_days
    unused_days = conf.stale_days.iam_key_unused_days
    now = datetime.now(timezone.utc)

    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page.get("Users", []):
            uname = user["UserName"]
            akp = iam.get_paginator("list_access_keys")
            for kp in akp.paginate(UserName=uname):
                for key in kp.get("AccessKeyMetadata", []):
                    kid = key["AccessKeyId"]
                    create = key.get("CreateDate")
                    age_days = (now - create).days if create else None

                    # Last used
                    last = iam.get_access_key_last_used(AccessKeyId=kid)
                    last_used = last.get("AccessKeyLastUsed", {}).get("LastUsedDate")
                    unused_for = (now - last_used).days if last_used else None

                    # Age check
                    if age_days is not None and age_days > max_age:
                        findings.append({
                            "account_id": account_id,
                            "region": "global",
                            "service": "IAM",
                            "resource_id": f"{uname}/{kid}",
                            "severity": "MEDIUM",
                            "title": "Access key exceeds max age",
                            "details": f"Age {age_days}d > {max_age}d",
                            "remediation": "Rotate or remove aged access key; prefer IAM roles.",
                            "tags": {},
                        })

                    # Unused check
                    if unused_for is None or unused_for > unused_days:
                        details = "Never used" if unused_for is None else f"Unused for {unused_for} days"
                        findings.append({
                            "account_id": account_id,
                            "region": "global",
                            "service": "IAM",
                            "resource_id": f"{uname}/{kid}",
                            "severity": "LOW",
                            "title": "Stale or never-used access key",
                            "details": details,
                            "remediation": "Disable or delete unused key; enforce key rotation policy.",
                            "tags": {},
                        })
    return findings
