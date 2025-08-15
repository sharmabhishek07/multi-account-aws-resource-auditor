from __future__ import annotations
import csv
import os

def write_csv(findings: list[dict], outdir: str):
    os.makedirs(outdir, exist_ok=True)
    path = os.path.join(outdir, "findings.csv")
    if not findings:
        with open(path, "w", newline="", encoding="utf-8") as f:
            f.write("")
        return path
    keys = ["account_id","region","service","resource_id","severity","title","details","remediation"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for row in findings:
            w.writerow({k: row.get(k, "") for k in keys})
    return path
