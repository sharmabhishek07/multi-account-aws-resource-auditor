import boto3

def scan_s3_buckets(account_id, region, findings):
    """
    Scan S3 buckets for various security issues, including lifecycle policy.
    """
    s3 = boto3.client('s3', region_name=region)

    buckets = s3.list_buckets().get("Buckets", [])
    for bucket in buckets:
        name = bucket["Name"]
        public = False
        bpa_off = False
        encryption_missing = False
        versioning_missing = False
        lifecycle_missing = False

        try:
            s3.get_bucket_acl(Bucket=name)
        except Exception:
            pass

        try:
            s3.get_bucket_policy_status(Bucket=name)
        except Exception:
            pass

        try:
            s3.get_bucket_encryption(Bucket=name)
        except s3.exceptions.ClientError:
            encryption_missing = True

        try:
            ver = s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                versioning_missing = True
        except Exception:
            pass

        try:
            lc = s3.get_bucket_lifecycle_configuration(Bucket=name)
            if not lc.get("Rules"):
                lifecycle_missing = True
        except s3.exceptions.ClientError:
            lifecycle_missing = True

        if public or bpa_off or encryption_missing or versioning_missing:
            issues = []
            if public:
                issues.append("public ACL/policy")
            if bpa_off:
                issues.append("Public Access Block not fully enabled")
            if encryption_missing:
                issues.append("encryption missing")
            if versioning_missing:
                issues.append("versioning not enabled")

            findings.append({
                "account_id": account_id,
                "region": region,
                "service": "S3",
                "resource_id": name,
                "severity": "MEDIUM",
                "title": "S3 bucket misconfigurations",
                "details": issues
            })

        if lifecycle_missing:
            findings.append({
                "account_id": account_id,
                "region": region,
                "service": "S3",
                "resource_id": name,
                "severity": "LOW",
                "title": "S3 bucket missing lifecycle policy",
                "details": {}
            })

def scan_s3(session, account_id, region, conf):
    findings = []
    s3 = session.client("s3", region_name=region)

    try:
        buckets = s3.list_buckets()["Buckets"]
        for bucket in buckets:
            name = bucket["Name"]

            # Example: check public access
            public = False
            try:
                pab = s3.get_bucket_policy_status(Bucket=name)
                if pab["PolicyStatus"]["IsPublic"]:
                    public = True
            except Exception:
                pass

            if public:
                findings.append({
                    "account_id": account_id,
                    "region": region,
                    "service": "S3",
                    "resource_id": name,
                    "severity": "HIGH",
                    "title": "S3 bucket is public",
                })

    except Exception as e:
        print(f"[WARN] {account_id} {region} s3: {e}")

    return findings
