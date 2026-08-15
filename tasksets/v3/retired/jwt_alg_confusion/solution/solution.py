import fnmatch

def _list(x):
    if x is None: return ["*"]
    return x if isinstance(x, list) else [x]

def _statements(policy):
    st = policy.get("Statement", [])
    return st if isinstance(st, list) else [st]

def _cond_ok(stmt):
    c = stmt.get("Condition")
    return not c or c == {"Bool": {"aws:MultiFactorAuthPresent": "true"}}

def _action_matches(pattern, action):
    if isinstance(pattern, tuple) and pattern[0] == "NOT":
        return not any(fnmatch.fnmatchcase(action.lower(), p.lower()) for p in pattern[1])
    return fnmatch.fnmatchcase(action.lower(), str(pattern).lower())

class IAMAnalyzer:
    def analyze(self, document):
        roles = document.get("roles", {})
        findings = []
        for ident, policy in document.get("identities", {}).items():
            allows = []
            denies = []
            boundary = document.get("permission_boundaries", {}).get(ident, {"Statement": []})
            for st in _statements(policy) + _statements(boundary):
                if st.get("Effect") == "Allow" and not _cond_ok(st):
                    continue
                bucket = allows if st.get("Effect") == "Allow" else denies if st.get("Effect") == "Deny" else None
                if bucket is not None:
                    actions = [("NOT", _list(st.get("NotAction")))] if "NotAction" in st else _list(st.get("Action"))
                    for a in actions:
                        for r in _list(st.get("Resource")):
                            bucket.append((a, r))
            def denied(action, res):
                return any(_action_matches(a, action) and fnmatch.fnmatchcase(res, r) for a, r in denies)
            def has(action, res="*"):
                for a, r in allows:
                    if _action_matches(a, action) and fnmatch.fnmatchcase(res, r) and not denied(action, res):
                        return a, r
                    if _action_matches(a, action) and r == "*" and not denied(action, res):
                        return a, r
                return None
            direct = None
            for act in ("*", "iam:*", "AdministratorAccess", "iam:CreatePolicyVersion"):
                direct = has(act, "*") or direct
            if direct:
                action_name = "NotAction allow" if isinstance(direct[0], tuple) else direct[0]
                findings.append({"identity": ident, "type": "DIRECT_ADMIN", "path": [f"{action_name} on {direct[1]}"]})
            admin_roles = [name for name, meta in roles.items() if meta.get("admin")]
            passed = [role for role in admin_roles if has("iam:PassRole", role)]
            if passed and (has("lambda:CreateFunction") or has("lambda:UpdateFunctionCode") or has("lambda:InvokeFunction") or has("lambda:*")):
                findings.append({"identity": ident, "type": "PASSROLE_LAMBDA_ADMIN", "path": [f"iam:PassRole {passed[0]}", "lambda code execution"]})
            if passed and has("ec2:RunInstances"):
                findings.append({"identity": ident, "type": "EC2_INSTANCE_PROFILE_ADMIN", "path": [f"iam:PassRole {passed[0]}", "ec2:RunInstances"]})
            cps = {r for a, r in allows if _action_matches(a, "iam:CreatePolicyVersion") and not denied("iam:CreatePolicyVersion", r)}
            sds = {r for a, r in allows if _action_matches(a, "iam:SetDefaultPolicyVersion") and not denied("iam:SetDefaultPolicyVersion", r)}
            common = sorted(cps & sds)
            if common:
                r = common[0]
                findings.append({"identity": ident, "type": "POLICY_VERSION_ESCALATION", "path": [f"iam:CreatePolicyVersion {r}", f"iam:SetDefaultPolicyVersion {r}"]})
        return sorted(findings, key=lambda x: (x["identity"], x["type"]))
