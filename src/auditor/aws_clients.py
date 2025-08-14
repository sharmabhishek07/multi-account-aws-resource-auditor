from __future__ import annotations
import boto3
from typing import Iterable, Dict, Any, Tuple, List

def org_client():
    return boto3.client("organizations")

def sts_client():
    return boto3.client("sts")

def list_accounts() -> List[dict]:
    client = org_client()
    accounts = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = client.list_accounts(**kwargs)
        accounts.extend(resp.get("Accounts", []))
        token = resp.get("NextToken")
        if not token:
            break
    return accounts

def assume_into_account(account_id: str, role_name: str, external_id: str | None = None):
    arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    sts = sts_client()
    params = {"RoleArn": arn, "RoleSessionName": "auditor-session"}
    if external_id:
        params["ExternalId"] = external_id
    creds = sts.assume_role(**params)["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    return session
