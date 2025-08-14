from __future__ import annotations
from .aws_clients import list_accounts, assume_into_account
from .config import Config, Account

def get_target_accounts(conf: Config) -> list[Account]:
    if conf.accounts:
        return [a for a in conf.accounts if a.id not in set(conf.exclude_accounts)]
    # Discover via Organizations
    discovered = []
    for a in list_accounts():
        if a["Id"] in set(conf.exclude_accounts): 
            continue
        discovered.append(Account(id=a["Id"], name=a.get("Name")))
    return discovered

def session_for(account_id: str, conf: Config):
    return assume_into_account(account_id, conf.assume_role_name, conf.external_id)
