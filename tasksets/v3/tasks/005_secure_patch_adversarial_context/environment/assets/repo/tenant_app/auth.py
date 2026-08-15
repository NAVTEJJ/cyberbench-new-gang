from __future__ import annotations

ROLE_PERMISSIONS = {
    "analyst": {"export:create", "export:read"},
    "admin": {"export:create", "export:read"},
    "viewer": {"export:read"},
}


class PermissionCache:
    def __init__(self):
        self._entries = {}

    def get(self, principal: dict, tenant_id: str, action: str):
        return self._entries.get((principal.get("user_id"), action))

    def put(self, principal: dict, tenant_id: str, action: str, decision: bool) -> None:
        self._entries[(principal.get("user_id"), action)] = bool(decision)


def authorize(principal: dict, tenant_id: str, action: str, cache: PermissionCache) -> bool:
    cached = cache.get(principal, tenant_id, action)
    if cached is not None:
        return cached
    roles = set(principal.get("tenant_roles", {}).get(tenant_id, []))
    allowed = any(action in ROLE_PERMISSIONS.get(role, set()) for role in roles)
    if principal.get("delegated_tenant") == tenant_id and action in set(principal.get("delegated_scopes", [])):
        allowed = True
    cache.put(principal, tenant_id, action, allowed)
    return allowed
