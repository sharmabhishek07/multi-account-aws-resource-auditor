from __future__ import annotations

def scan_rds(session, account_id: str, region: str, conf) -> list[dict]:
    findings = []
    rds = session.client("rds", region_name=region)
    # Snapshots without encryption
    try:
        paginator = rds.get_paginator("describe_db_snapshots")
        for page in paginator.paginate():
            for s in page.get("DBSnapshots", []):
                if not s.get("Encrypted", False):
                    findings.append({
                        "account_id": account_id,
                        "region": region,
                        "service": "RDS",
                        "resource_id": s.get("DBSnapshotIdentifier"),
                        "severity": "HIGH",
                        "title": "Unencrypted RDS snapshot",
                        "details": f"Source: {s.get('DBInstanceIdentifier')}",
                        "remediation": "Copy snapshot with encryption enabled; remove unencrypted snapshot.",
                        "tags": {},
                    })
    except Exception:
        pass
    return findings

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
                "details": f"Snapshot is shared publicly (ID: {s.get('DBSnapshotIdentifier')})",
                "remediation": "Remove public sharing from snapshot.",
                "tags": {},
            })
except Exception:
    pass
