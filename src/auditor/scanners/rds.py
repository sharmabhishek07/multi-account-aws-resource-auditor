import boto3

def scan_rds_public_snapshots(account_id, region, findings):
    """
    Scan for public/shared RDS snapshots.
    """
    rds = boto3.client('rds', region_name=region)

    # Public snapshots
    try:
        for s in rds.describe_db_snapshots(SnapshotType="shared")["DBSnapshots"]:
            if s.get("SnapshotType") == "shared":
                findings.append({
                    "account_id": account_id,
                    "region": region,
                    "service": "RDS",
                    "resource_id": s.get("DBSnapshotIdentifier"),
                    "severity": "HIGH",
                    "title": "Public RDS snapshot",
                    "details": s
                })
    except rds.exceptions.ClientError as e:
        print(f"Error checking RDS snapshots in {region}: {e}")

def scan_rds(session, account_id, region, conf):
    findings = []
    rds = session.client("rds", region_name=region)

    try:
        instances = rds.describe_db_instances()["DBInstances"]
        for db in instances:
            if db.get("PubliclyAccessible"):
                findings.append({
                    "account_id": account_id,
                    "region": region,
                    "service": "RDS",
                    "resource_id": db["DBInstanceIdentifier"],
                    "severity": "HIGH",
                    "title": "Publicly accessible RDS instance",
                })
    except Exception as e:
        print(f"[WARN] {account_id} {region} rds: {e}")

    return findings
