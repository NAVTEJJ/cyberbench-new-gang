class ADAttackGraph:
    def analyze(self, directory):
        principals=directory.get("principals",{});groups=directory.get("groups",{})
        def memberships(p):
            seen=set([p]);changed=True
            while changed:
                changed=False
                for g,parents in groups.items():
                    if g in seen:
                        for x in parents:
                            if x not in seen:seen.add(x);changed=True
                for g,parents in groups.items():
                    if any(x in seen for x in parents) and g not in seen:
                        seen.add(g);changed=True
                for x in principals.get(p,{}).get("groups",[]):
                    if x not in seen:seen.add(x);changed=True
            return seen
        out=[]
        for p,meta in principals.items():
            if not meta.get("lowpriv"):continue
            mem=memberships(p)
            for n,m in principals.items():
                if m.get("spn") and not m.get("aes_only"):
                    out.append({"principal":p,"type":"KERBEROAST","target":n,"path":[p,m["spn"][0]]})
                if m.get("preauth") is False and not m.get("disabled"):
                    out.append({"principal":p,"type":"ASREP_ROAST","target":n,"path":[p,n]})
            for ace in directory.get("aces",[]):
                if ace.get("effect")=="allow" and ace.get("principal") in mem and ace.get("right")=="write_rbcd":
                    out.append({"principal":p,"type":"RBCD_TAKEOVER","target":ace["target"],"path":[p,ace["principal"],ace["target"]]})
                if ace.get("effect")=="allow" and ace.get("principal") in mem and ace.get("right")=="dcsync":
                    out.append({"principal":p,"type":"DCSYNC","target":ace["target"],"path":[p,"Helpdesk",ace["principal"],ace["target"]]})
            for name,t in directory.get("templates",{}).items():
                if t.get("enrollee_supplies_subject") and t.get("client_auth") and any(e in mem for e in t.get("enrollers",[])):
                    out.append({"principal":p,"type":"ADCS_ESCALATION","target":name,"path":[p,t["enrollers"][0],"enroll"]})
        order={"ADCS_ESCALATION":0,"ASREP_ROAST":1,"DCSYNC":2,"KERBEROAST":3,"RBCD_TAKEOVER":4}
        return sorted(out,key=lambda x:(x["principal"],order[x["type"]],x["target"]))
