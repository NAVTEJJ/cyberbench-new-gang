import fnmatch, re, unicodedata, urllib.parse

BIDI=set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
DEV={"con","prn","aux","nul",*(f"com{i}" for i in range(1,10)),*(f"lpt{i}" for i in range(1,10))}

class PathFirewall:
    def _decode(self,p):
        for i in range(4):
            if re.search(r"%(?![0-9a-fA-F]{2})",p):raise ValueError("bad percent")
            q=urllib.parse.unquote(p)
            if q==p:return q
            p=q
        raise ValueError("too much encoding")
    def _canon(self,p,policy):
        p=self._decode(str(p))
        if "\x00" in p or any(c in p for c in BIDI):raise ValueError("unsafe char")
        p=unicodedata.normalize("NFKC",p).replace("\\","/")
        if policy.get("case_insensitive"):p=p.casefold()
        if p.startswith("/") or p.startswith("//") or re.match(r"^[a-z]:",p):raise ValueError("absolute")
        root=policy["root"].rstrip("/")
        parts=[]
        for raw in [x for x in p.split("/") if x and x!="."]:
            if raw=="..":
                if parts:parts.pop()
                else:raise ValueError("escape")
                continue
            if ":" in raw or raw.split(".")[0] in DEV:raise ValueError("reserved")
            parts.append(raw)
            cur=root+"/"+"/".join(parts)
            seen=set()
            while cur in policy.get("symlinks",{}):
                if cur in seen:raise ValueError("cycle")
                seen.add(cur);target=policy["symlinks"][cur]
                if not target.startswith(root+"/"):raise ValueError("symlink escape")
                parts=target[len(root)+1:].split("/")
                cur=target
        final=root+("/"+"/".join(parts) if parts else "")
        if final!=root and not final.startswith(root+"/"):raise ValueError("escape")
        ext="."+final.rsplit(".",1)[-1] if "." in final.rsplit("/",1)[-1] else ""
        if policy.get("allow_extensions") and ext not in [e.casefold() for e in policy["allow_extensions"]]:raise ValueError("extension")
        rel=final[len(root)+1:]
        if any(fnmatch.fnmatch(rel,g) for g in policy.get("deny_globs",[])):raise ValueError("deny glob")
        return final
    def decide(self,request,policy):
        try:
            if request.get("mode")=="archive":
                for e in request.get("entries",[]):
                    if e.get("type")=="symlink":raise ValueError("archive symlink")
                    self._canon(e.get("name",""),policy)
                return {"allow":True,"canonical":policy["root"].rstrip("/"),"reason":"ok"}
            c=self._canon(request.get("path",""),policy)
            return {"allow":True,"canonical":c,"reason":"ok"}
        except Exception as exc:
            return {"allow":False,"canonical":"","reason":str(exc)}
