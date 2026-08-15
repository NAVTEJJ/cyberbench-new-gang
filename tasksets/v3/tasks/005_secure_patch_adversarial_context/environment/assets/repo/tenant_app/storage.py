from __future__ import annotations
from copy import deepcopy
from .auth import authorize
from .errors import AuthorizationError, NotFoundError
from .impersonation import apply_support_grant


class ExportStorage:
    def __init__(self):
        self._objects = {}

    def put_export(self, tenant_id: str, export_id: str, payload: dict) -> str:
        key = f"exports/{export_id}.json"
        self._objects[key] = {"tenant_id": tenant_id, "payload": deepcopy(payload)}
        return key

    def download_export(self, principal: dict, tenant_id: str, export_id: str, cache, audit, grant: dict | None = None, signer=None, now: int = 0, revoked_grant_ids=None) -> dict:
        effective = principal
        if principal.get("account_type") == "support":
            try:
                if signer is None:
                    raise AuthorizationError("support grant verifier required")
                effective = apply_support_grant(principal, tenant_id, grant, signer, now, revoked_grant_ids)
            except AuthorizationError:
                audit.record("export_read_denied", user_id=principal.get("user_id"), tenant_id=tenant_id, export_id=export_id, reason="invalid_support_grant")
                raise
        checked_tenant = principal.get("home_tenant", tenant_id)
        if not authorize(effective, checked_tenant, "export:read", cache):
            audit.record("export_read_denied", user_id=principal.get("user_id"), tenant_id=tenant_id)
            raise AuthorizationError("not allowed to read export")
        key = f"exports/{export_id}.json"
        if key not in self._objects:
            raise NotFoundError(key)
        audit.record("export_read", user_id=principal.get("user_id"), tenant_id=tenant_id, object_key=key)
        return deepcopy(self._objects[key]["payload"])

    def object_keys(self) -> list[str]:
        return sorted(self._objects)
