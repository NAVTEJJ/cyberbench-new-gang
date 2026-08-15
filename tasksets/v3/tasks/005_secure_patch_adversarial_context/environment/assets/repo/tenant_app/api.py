from __future__ import annotations
from .auth import authorize
from .errors import AuthorizationError
from .impersonation import apply_support_grant


def request_export(principal: dict, request: dict, cache, signer, audit, grant: dict | None = None, now: int = 0, revoked_grant_ids=None) -> dict:
    target_tenant = request["tenant_id"]
    try:
        effective = apply_support_grant(principal, target_tenant, grant, signer, now, revoked_grant_ids)
    except AuthorizationError:
        audit.record("export_request_denied", user_id=principal.get("user_id"), tenant_id=target_tenant, request_id=request.get("request_id"), reason="invalid_support_grant")
        raise
    checked_tenant = effective.get("home_tenant", target_tenant)
    if not authorize(effective, checked_tenant, "export:create", cache):
        audit.record("export_request_denied", user_id=principal.get("user_id"), tenant_id=target_tenant)
        raise AuthorizationError("not allowed to create export")
    payload = {
        "kind": "export_authorization",
        "user_id": effective.get("user_id"),
        "tenant_id": target_tenant,
        "action": "export:create",
        "request_id": request["request_id"],
        "expires_at": int(now) + 300,
    }
    job = {
        "job_id": f"job-{request['request_id']}",
        "request_id": request["request_id"],
        "export_id": request["export_id"],
        "tenant_id": target_tenant,
        "requested_by": effective.get("user_id"),
        "authorization": signer.sign(payload),
    }
    audit.record("export_request_accepted", user_id=principal.get("user_id"), tenant_id=target_tenant, request_id=request["request_id"])
    return job
