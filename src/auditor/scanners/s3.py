from __future__ import annotations

def scan_s3(session, account_id: str, region: str, conf) -> list[dict]:
    findings = []
    s3 = session.client("s3", region_name=region)
    # S3 buckets are global; we run once per region but results are same. Filter to avoid dupes.
    buckets = s3.list_buckets().get("Buckets", [])
    for b in buckets:
        name = b["Name"]
        # Public check
        public = False
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for g in acl.get("Grants", []):
                grantee = g.get("Grantee", {})
                if grantee.get("URI", "").endswith("AllUsers") or grantee.get("URI", "").endswith("AuthenticatedUsers"):
                    public = True
        except Exception:
            pass

        # Block Public Access check
        bpa_off = False
        try:
            bpa = s3.get_public_access_block(Bucket=name)
            cfg = bpa.get("PublicAccessBlockConfiguration", {})
            bpa_off = not all(cfg.values())
        except Exception:
            # no BPA -> effectively not enforced
            bpa_off = True

        # Encryption
        encryption_missing = False
        try:
            s3.get_bucket_encryption(Bucket=name)
        except Exception:
            encryption_missing = True

        # Versioning
        versioning_missing = False
        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            versioning_missing = ver.get("Status") != "Enabled"
        except Exception:
            versioning_missing = True

        if public or bpa_off or encryption_missing or versioning_missing:
            issues = []
            if public: issues.append("public ACL/policy")
            if bpa_off: issues.append("Public Access Block not fully enabled")
            if encryption_missing: issues.append("encryption missing")
            if versioning_missing: issues.append("versioning not enabled")
            findings.append({
                "account_id": account_id,
                "region": region,
                "service": "S3",
                "resource_id": name,
                "severity": "HIGH" if public else "MEDIUM",
                "title": "S3 bucket misconfiguration",
                "details": ", ".join(issues),
                "remediation": "Enable Block Public Access, default encryption, and versioning; review bucket policy/ACL.",
                "tags": {},
            })
    return findings

# Lifecycle configuration
lifecycle_missing = False
try:
    lc = s3.get_bucket_lifecycle_configuration(Bucket=name)
    if not lc.get("Rules"):
        lifecycle_missing = True
except Exception:
    lifecycle_missing = True

if lifecycle_missing:
    findings.append({
        "account_id": account_id,
        "region": region,
        "service": "S3",
        "resource_id": name,
        "severity": "LOW",
        "title": "S3 bucket missing lifecycle policy",
        "details": "No lifecycle rules found (may lead to unnecessary storage costs)",
        "remediation": "Add lifecycle rules to transition or expire old objects.",
        "tags": {},
    })
