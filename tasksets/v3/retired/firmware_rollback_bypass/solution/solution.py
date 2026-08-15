def anymatch(items, want):
    return "*" in items or want in items

class K8sAdmissionAnalyzer:
    def analyze(self, cluster):
        roles = cluster.get("roles", {})
        rights = {}
        for b in cluster.get("bindings", []):
            role = roles.get(b.get("role"), {})
            for s in b.get("subjects", []):
                if s.get("kind") == "ServiceAccount":
                    ns = s.get("namespace") or b.get("namespace")
                    rights.setdefault((ns, s.get("name")), []).extend(role.get("rules", []))
        out = []
        for p in cluster.get("pods", []):
            ns, pod = p.get("namespace","default"), p.get("name","")
            sa = p.get("serviceAccount","default")
            containers = p.get("initContainers", []) + p.get("containers", []) + p.get("ephemeralContainers", [])
            vols = {v.get("name"): v for v in p.get("volumes", [])}
            for v in vols.values():
                hp = v.get("hostPath", {}).get("path")
                if hp in ("/", "/var/run/docker.sock", "/proc", "/sys", "/var/lib/kubelet"):
                    out.append({"namespace":ns,"pod":pod,"type":"HOST_ESCAPE","evidence":f"hostPath {hp}"})
            host_ns = p.get("hostPID") or p.get("hostNetwork")
            broad_egress = False
            for c in containers:
                sc = {**p.get("securityContext", {}), **c.get("securityContext", {})}
                caps = sc.get("capabilities", {}).get("add", [])
                if sc.get("privileged"):
                    out.append({"namespace":ns,"pod":pod,"type":"HOST_ESCAPE","evidence":"privileged container"})
                if host_ns and any(x in caps for x in ("SYS_ADMIN","NET_ADMIN","SYS_PTRACE")):
                    out.append({"namespace":ns,"pod":pod,"type":"HOST_ESCAPE","evidence":"host namespace with SYS_ADMIN"})
                if "0.0.0.0/0" in c.get("egress", []) or "::/0" in c.get("egress", []):
                    broad_egress = True
            rules = rights.get((ns, sa), [])
            def can(verb, res):
                return any(anymatch(r.get("verbs",[]), verb) and anymatch(r.get("resources",[]), res) for r in rules)
            if can("create","clusterrolebindings") or can("update","clusterrolebindings") or can("impersonate","users") or can("bind","clusterroles") or can("escalate","clusterroles"):
                out.append({"namespace":ns,"pod":pod,"type":"RBAC_ESCALATION","evidence":"create clusterrolebindings"})
            token = p.get("automountServiceAccountToken", True)
            if token and broad_egress and (can("get","secrets") or can("list","secrets")) and can("create","clusterrolebindings"):
                out.append({"namespace":ns,"pod":pod,"type":"TOKEN_STEAL","evidence":"token plus secrets and api egress"})
            if broad_egress and not cluster.get("namespaces", {}).get(ns, {}).get("defaultDenyEgress", False):
                out.append({"namespace":ns,"pod":pod,"type":"POLICY_BYPASS","evidence":"no default deny egress"})
        return sorted(out, key=lambda x:(x["namespace"], x["pod"], x["type"], x["evidence"]))
