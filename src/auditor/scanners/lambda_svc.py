from __future__ import annotations
from datetime import datetime, timezone, timedelta

def scan_lambda(session, account_id: str, region: str, conf) -> list[dict]:
    findings = []
    lam = session.client("lambda", region_name=region)
    cw = session.client("cloudwatch", region_name=region)

    paginator = lam.get_paginator("list_functions")
    cutoff = datetime.now(timezone.utc) - timedelta(days=conf.stale_days.lambda_no_invocations)
    for page in paginator.paginate():
        for fn in page.get("Functions", []):
            name = fn["FunctionName"]
            # No invocation in period?
            metrics = cw.get_metric_statistics(
                Namespace="AWS/Lambda",
                MetricName="Invocations",
                Dimensions=[{"Name": "FunctionName", "Value": name}],
                StartTime=cutoff,
                EndTime=datetime.now(timezone.utc),
                Period=24 * 3600,
                Statistics=["Sum"],
            )
            total_invocations = sum(pt.get("Sum", 0) for pt in metrics.get("Datapoints", []))
            if total_invocations == 0:
                findings.append({
                    "account_id": account_id,
                    "region": region,
                    "service": "Lambda",
                    "resource_id": name,
                    "severity": "LOW",
                    "title": "Lambda not invoked recently",
                    "details": f"No invocations since {cutoff.date()}",
                    "remediation": "Remove unused function or document why it is idle.",
                    "tags": {},
                })
            # Missing tags
            try:
                tags = lam.list_tags(Resource=fn["FunctionArn"]).get("Tags", {})
                if not tags:
                    findings.append({
                        "account_id": account_id,
                        "region": region,
                        "service": "Lambda",
                        "resource_id": name,
                        "severity": "LOW",
                        "title": "Lambda missing tags",
                        "details": "No tags present on function",
                        "remediation": "Add ownership/cost-center/environment tags.",
                        "tags": {},
                    })
            except Exception:
                pass
    return findings
