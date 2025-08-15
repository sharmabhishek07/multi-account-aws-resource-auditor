from __future__ import annotations
import argparse
import sys
import os
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
from auditor.scanners.ec2 import scan_ec2_unused_eips
from auditor.scanners.rds import scan_rds_public_snapshots
from auditor.scanners.s3 import scan_s3_buckets

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

def run(config_path: str, only: list[str] | None, outdir: str | None, demo: bool = False):
    conf = load_config(config_path)
    if outdir:
        conf.output_dir = outdir

    accounts = get_target_accounts(conf)
    print(f"Discovered/target accounts: {[a.id for a in accounts]}")

    all_findings = []

    for acct in accounts:
        sess = None
        regions = ["us-east-1"]  # fallback region

        if not demo:
            try:
                sess = session_for(acct.id, conf)
                regions = conf.regions or discover_regions(sess)
            except Exception as e:
                print(f"[WARN] {acct.id}: {e}", file=sys.stderr)
                continue
        else:
            print(f"[INFO] Demo mode: skipping AWS calls for {acct.id}")

        # IAM is global
        try:
            f = SERVICES["iam"](sess, acct.id, "global", conf) if sess else []
            all_findings.extend(f)
            print(f"[OK] {acct.id} iam: {len(f)} findings")
        except Exception as e:
            print(f"[WARN] {acct.id} iam: {e}", file=sys.stderr)

        # Per-region service scans
        for region in regions:
            for svc, fn in SERVICES.items():
                if svc == "iam":
                    continue
                if only and svc not in only:
                    continue
                try:
                    f = fn(sess, acct.id, region, conf) if sess else []
                    all_findings.extend(f)
                    print(f"[OK] {acct.id} {region} {svc}: {len(f)} findings")
                except Exception as e:
                    print(f"[WARN] {acct.id} {region} {svc}: {e}", file=sys.stderr)

            # Extra custom checks
            try:
                extra_findings = []
                scan_ec2_unused_eips(acct.id, region, extra_findings)
                scan_rds_public_snapshots(acct.id, region, extra_findings)
                scan_s3_buckets(acct.id, region, extra_findings)
                all_findings.extend(extra_findings)
                print(f"[OK] {acct.id} {region} extra-scanners: {len(extra_findings)} findings")
            except Exception as e:
                print(f"[WARN] {acct.id} {region} extra-scanners: {e}", file=sys.stderr)

    # Write output
    os.makedirs(conf.output_dir, exist_ok=True)
    csv_path = write_csv(all_findings, conf.output_dir)
    html_path = write_html(all_findings, conf.output_dir, datetime.now(timezone.utc).isoformat())
    print(f"Wrote: {csv_path}\nWrote: {html_path}")

def parse_args(argv):
    p = argparse.ArgumentParser(description="Multi-Account AWS Resource Auditor")
    p.add_argument("--config", required=True, help="Path to config.yaml")
    p.add_argument("--only", help="Comma-separated services: ec2,s3,lambda,rds,iam")
    p.add_argument("--out", help="Output directory")
    p.add_argument("--demo", action="store_true", help="Run in demo mode without AWS calls")
    args = p.parse_args(argv)
    only = args.only.split(",") if args.only else None
    return args.config, only, args.out, args.demo

if __name__ == "__main__":
    config_path, only, out, demo = parse_args(sys.argv[1:])
    run(config_path, only, out, demo)
