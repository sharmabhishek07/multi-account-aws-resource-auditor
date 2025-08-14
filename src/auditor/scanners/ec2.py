from __future__ import annotations
from datetime import datetime, timezone, timedelta

def scan_ec2(session, account_id: str, region: str, conf) -> list[dict]:
    findings = []
    ec2 = session.client("ec2", region_name=region)

    # Stopped instances older than threshold
    resp = ec2.describe_instances(
        Filters=[{"Name": "instance-state-name", "Values": ["stopped"]}]
    )
    cutoff = datetime.now(timezone.utc) - timedelta(days=conf.stale_days.ec2_stopped_older_than)
    for r in resp.get("Reservations", []):
        for inst in r.get("Instances", []):
            launch = inst.get("LaunchTime")
            if launch and launch < cutoff:
                findings.append({
                    "account_id": account_id,
                    "region": region,
                    "service": "EC2",
                    "resource_id": inst.get("InstanceId"),
                    "severity": "MEDIUM",
                    "title": "EC2 instance stopped for a long time",
                    "details": f"Launch time {launch.isoformat()} is older than cutoff {cutoff.date()}",
                    "remediation": "Terminate if not needed or start and use; consider creating AMI before termination.",
                    "tags": {t['Key']: t.get('Value') for t in inst.get('Tags', [])} if inst.get('Tags') else {},
                })

    # Unattached EBS volumes
    vols = ec2.describe_volumes(Filters=[{"Name": "status", "Values": ["available"]}]).get("Volumes", [])
    for v in vols:
        findings.append({
            "account_id": account_id,
            "region": region,
            "service": "EBS",
            "resource_id": v.get("VolumeId"),
            "severity": "HIGH",
            "title": "Unattached EBS volume",
            "details": f"Size {v.get('Size')} GiB, type {v.get('VolumeType')}",
            "remediation": "Delete or snapshot unattached volume to reduce costs.",
            "tags": {t['Key']: t.get('Value') for t in v.get('Tags', [])} if v.get('Tags') else {},
        })

    # Security groups with open ingress (0.0.0.0/0 or ::/0)
    sgs = ec2.describe_security_groups().get("SecurityGroups", [])
    for sg in sgs:
        sg_id = sg.get("GroupId")
        for perm in sg.get("IpPermissions", []):
            ipv4_open = any(ipr.get("CidrIp") == "0.0.0.0/0" for ipr in perm.get("IpRanges", []))
            ipv6_open = any(ipr.get("CidrIpv6") == "::/0" for ipr in perm.get("Ipv6Ranges", []))
            if ipv4_open or ipv6_open:
                proto = perm.get("IpProtocol")
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")
                port_desc = f"{from_p}-{to_p}" if from_p not in (None, -1) and to_p not in (None, -1) else "all"
                findings.append({
                    "account_id": account_id,
                    "region": region,
                    "service": "EC2",
                    "resource_id": sg_id,
                    "severity": "HIGH",
                    "title": "Security group open to the world",
                    "details": f"{proto} ports {port_desc} open to 0.0.0.0/0 or ::/0",
                    "remediation": "Restrict to specific CIDRs or use Security Group references; remove wide-open rules.",
                    "tags": {t['Key']: t.get('Value') for t in sg.get('Tags', [])} if sg.get('Tags') else {},
                })
    return findings

# Unused Elastic IPs (no association)
eips = ec2.describe_addresses().get("Addresses", [])
for eip in eips:
    if "InstanceId" not in eip and "NetworkInterfaceId" not in eip:
        findings.append({
            "account_id": account_id,
            "region": region,
            "service": "EC2",
            "resource_id": eip.get("PublicIp"),
            "severity": "MEDIUM",
            "title": "Unused Elastic IP",
            "details": "Allocated but not associated",
            "remediation": "Release unused EIP to avoid charges.",
            "tags": {},
        })
