import boto3

def scan_ec2_unused_eips(account_id, region, findings):
    """
    Scan for unused Elastic IPs in the given account and region.
    """
    ec2 = boto3.client('ec2', region_name=region)

    # Unused Elastic IPs (no association)
    eips = ec2.describe_addresses().get("Addresses", [])
    for eip in eips:
        if "InstanceId" not in eip and "NetworkInterfaceId" not in eip:
            findings.append({
                "account_id": account_id,
                "region": region,
                "service": "EC2",
                "resource_id": eip.get("PublicIp"),
                "severity": "LOW",
                "title": "Unused Elastic IP",
                "details": eip
            })

def scan_ec2(session, account_id, region, conf):
    findings = []
    ec2 = session.client("ec2", region_name=region)

    # Example: Security groups open to 0.0.0.0/0
    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
        for sg in sgs:
            for perm in sg.get("IpPermissions", []):
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "account_id": account_id,
                            "region": region,
                            "service": "EC2",
                            "resource_id": sg["GroupId"],
                            "severity": "MEDIUM",
                            "title": "Security group open to the world",
                        })
    except Exception as e:
        print(f"[WARN] {account_id} {region} ec2: {e}")

    return findings
