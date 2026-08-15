class MobileSecurityAuditor:
    def audit(self,app):
        out=[]
        for c in app.get("components",[]):
            if c.get("exported") and c.get("browsable") and (not c.get("autoVerify")) and (any("*" in x for x in c.get("hosts",[])+c.get("paths",[]))) and any("oauth" in a or "token" in a for a in c.get("actions",[])):
                out.append({"component":c["name"],"type":"DEEPLINK_TAKEOVER","evidence":f"wildcard unverified {c['actions'][0]}"})
            if c.get("exported") and any("PRIVILEGED" in a or "ADMIN" in a for a in c.get("actions",[])) and c.get("permission")!="signature":
                out.append({"component":c["name"],"type":"EXPORTED_PRIVILEGED_COMPONENT","evidence":f"{c['actions'][0]} without signature permission"})
        for w in app.get("webviews",[]):
            bridge=next((b for b in w.get("bridges",[]) if "*" in b.get("origins",[]) or "exec" in b.get("methods",[])),None)
            if w.get("javascript") and (w.get("file_access") or w.get("content_access")) and bridge:
                out.append({"component":w["name"],"type":"WEBVIEW_RCE","evidence":"javascript file/content access bridge *"})
        net=app.get("network",{})
        for d in set(net.get("cleartext",[])+net.get("pinning_disabled",[])):
            if app.get("release") and (d in net.get("cleartext",[]) or net.get("user_ca") or d in net.get("pinning_disabled",[])):
                out.append({"component":"network","type":"CLEAR_TEXT_TLS_BYPASS","evidence":f"{d} cleartext/user-ca/no-pinning"})
        if app.get("backup"):
            for s in app.get("secrets",[]):
                if any(x in s.lower() for x in ("token","secret","session","key")):
                    out.append({"component":"application","type":"BACKUP_SECRET_LEAK","evidence":s});break
        order={"WEBVIEW_RCE":0,"DEEPLINK_TAKEOVER":1,"EXPORTED_PRIVILEGED_COMPONENT":2,"BACKUP_SECRET_LEAK":3,"CLEAR_TEXT_TLS_BYPASS":4}
        return sorted(out,key=lambda x:(x["component"],order.get(x["type"],9),x["evidence"]))
