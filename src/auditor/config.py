from __future__ import annotations
import yaml
from dataclasses import dataclass, field
from typing import List

@dataclass
class Account:
    id: str
    name: str | None = None

@dataclass
class StaleDays:
    lambda_no_invocations: int = 30
    ec2_stopped_older_than: int = 7
    iam_key_unused_days: int = 60
    iam_key_max_age_days: int = 90

@dataclass
class Config:
    assume_role_name: str = "OrganizationAccountAccessRole"
    external_id: str | None = None
    regions: List[str] | None = None
    exclude_accounts: List[str] = field(default_factory=list)
    accounts: List[Account] = field(default_factory=list)
    output_dir: str = "./out"
    stale_days: StaleDays = field(default_factory=StaleDays)

def load_config(path: str) -> Config:
    with open(path, "r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}
    accounts = [Account(**a) for a in raw.get("accounts", [])]
    sd = raw.get("stale_days", {}) or {}
    conf = Config(
        assume_role_name=raw.get("assume_role_name", "OrganizationAccountAccessRole"),
        external_id=raw.get("external_id"),
        regions=raw.get("regions"),
        exclude_accounts=raw.get("exclude_accounts", []),
        accounts=accounts,
        output_dir=raw.get("output_dir", "./out"),
        stale_days=StaleDays(
            lambda_no_invocations=sd.get("lambda_no_invocations", 30),
            ec2_stopped_older_than=sd.get("ec2_stopped_older_than", 7),
            iam_key_unused_days=sd.get("iam_key_unused_days", 60),
            iam_key_max_age_days=sd.get("iam_key_max_age_days", 90),
        )
    )
    return conf
