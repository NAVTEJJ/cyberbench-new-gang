from __future__ import annotations
from copy import deepcopy
from .errors import AuthorizationError


def apply_support_grant(principal: dict, tenant_id: str, grant: dict | None, signer, now: int, revoked_grant_ids=None) -> dict:
    if principal.get("account_type") != "support":
        return deepcopy(principal)
    if not grant:
        raise AuthorizationError("support grant required")
    payload = grant.get("payload", grant)
    if int(payload.get("expires_at", 0)) < int(now):
        raise AuthorizationError("support grant expired")
    effective = deepcopy(principal)
    effective["delegated_tenant"] = tenant_id
    effective["delegated_scopes"] = list(payload.get("scopes", []))
    effective["delegated_grant_id"] = payload.get("grant_id")
    return effective
