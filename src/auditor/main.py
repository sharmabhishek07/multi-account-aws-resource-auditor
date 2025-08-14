from __future__ import annotations
import argparse, sys, os
from datetime import datetime, timezone

from .config import load_config
from .assume import get_target_accounts, session_for
from .reporters.csv_reporter import write_csv
from .reporters.html_reporter import write_html
from .scanners import ec2 as ec2_scan
from .scanners import s3 as s3_scan
from .scanners import lambda_svc as lambda_scan
from .scanners import rds as rds_scan
from .scanners import iam as iam_scan

SERVICES = {
    "ec2": ec2_scan.scan_ec2,
    "s3": s3_scan.scan_s3,
    "lambda": lambda_scan.scan_lambda,
    "rds": rds_scan.scan_rds,
    "iam": iam_scan.scan_iam,
}

def discover_regions(session):
    ec2 = session.client("ec2", region_name="us-east-1")
    resp = ec2.describe_regions(AllRegions=False)
    return sorted([r["RegionName"] for r in resp.get("Regions", [])])

def run(config_path: str, only: list[str] | None, outdir: str | None):
    conf = load_config(config_path)
    if outdir:
        conf.output_dir = outdir

    accounts = get_target_accounts(conf)
    print(f"Discovered/target accounts: {[a.id for a in accounts]}")

    all_findings = []
    for acct in accounts:
        try:
            sess = session_for(acct.id, conf)
        except Exception as e:
            print(f"[WARN] AssumeRole failed for {acct.id}: {e}", file=sys.stderr)
            continue

        regions = conf.regions or discover_regions(sess)
        # IAM is global, handle once per account
        try:
            f = SERVICES["iam"](sess, acct.id, "global", conf)
            all_findings.extend(f)
            print(f"[OK] {acct.id} iam: {len(f)} findings")
        except Exception as e:
            print(f"[WARN] {acct.id} iam: {e}", file=sys.stderr)

        for region in regions:
            for svc, fn in SERVICES.items():
                if svc == "iam":
                    continue
                if only and svc not in only:
                    continue
                try:
                    f = fn(sess, acct.id, region, conf)
                    all_findings.extend(f)
                    print(f"[OK] {acct.id} {region} {svc}: {len(f)} findings")
                except Exception as e:
                    print(f"[WARN] {acct.id} {region} {svc}: {e}", file=sys.stderr)

    os.makedirs(conf.output_dir, exist_ok=True)
    csv_path = write_csv(all_findings, conf.output_dir)
    html_path = write_html(all_findings, conf.output_dir, datetime.now(timezone.utc).isoformat())
    print(f"Wrote: {csv_path}\nWrote: {html_path}")

def parse_args(argv):
    p = argparse.ArgumentParser(description="Multi-Account AWS Resource Auditor")
    p.add_argument("--config", required=True, help="Path to config.yaml")
    p.add_argument("--only", help="Comma-separated services: ec2,s3,lambda,rds,iam")
    p.add_argument("--out", help="Output directory")
    args = p.parse_args(argv)
    only = args.only.split(",") if args.only else None
    return args.config, only, args.out

if __name__ == "__main__":
    import sys
    config_path, only, out = parse_args(sys.argv[1:])
    run(config_path, only, out)
