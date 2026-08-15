from urllib.parse import urlparse
import re

def csp_directives(csp):
    d={}
    for part in csp.split(";"):
        toks=part.strip().split()
        if toks:d[toks[0]]=toks[1:]
    return d

class BrowserPolicyAuditor:
    def audit(self, observations):
        out=[];nonces={}
        for o in observations:
            url=o.get("url","");h=o.get("headers",{})
            csp=h.get("Content-Security-Policy","");d=csp_directives(csp);script=" ".join(d.get("script-src",[]))
            for n in re.findall(r"'nonce-([^']+)'",script):
                if n in nonces and nonces[n]!=url:
                    out.append({"url":url if url<nonces[n] else nonces[n],"type":"CSP_BYPASS","evidence":f"nonce {n} reused"})
                nonces[n]=url
            if "base" in o.get("reflections",[]) and "base-uri" not in d:
                out.append({"url":url,"type":"CSP_BYPASS","evidence":"missing base-uri with reflected base"})
            if ("*" in script or "jsonp" in script or "'unsafe-inline'" in script) and o.get("sources") and any(s in o.get("sinks",[]) for s in ("innerHTML","eval","document.write")):
                out.append({"url":url,"type":"DOM_XSS_REACHABLE","evidence":f"{o['sources'][0]} -> {next(s for s in o['sinks'] if s in ('innerHTML','eval','document.write'))}"})
            if h.get("Access-Control-Allow-Credentials","").lower()=="true":
                acao=h.get("Access-Control-Allow-Origin","")
                if acao==o.get("request_origin") or "*" in acao:
                    out.append({"url":url,"type":"CORS_CREDENTIAL_LEAK","evidence":"credentialed reflected origin"})
            ck=h.get("Set-Cookie","")
            if ck:
                name=ck.split("=",1)[0];low=ck.lower()
                dom=""
                for p in ck.split(";"):
                    if p.strip().lower().startswith("domain="):dom=p.strip().split("=",1)[1]
                missing=[x for x in ("secure","httponly","samesite") if x not in low]
                broad=dom.startswith(".") and dom.count(".")<=1
                if missing or broad:
                    out.append({"url":url,"type":"COOKIE_SCOPE_LEAK","evidence":f"{name} domain {dom} missing Secure/HttpOnly/SameSite"})
            chain=o.get("redirect_chain",[])
            if len(chain)>=3 and "evil." in urlparse(chain[-1]).netloc and not "evil." in urlparse(chain[0]).netloc:
                out.append({"url":url,"type":"OPEN_REDIRECT_CHAIN","evidence":f"trusted chain to {urlparse(chain[-1]).netloc}"})
        order={"COOKIE_SCOPE_LEAK":0,"CORS_CREDENTIAL_LEAK":0,"CSP_BYPASS":1,"DOM_XSS_REACHABLE":2,"OPEN_REDIRECT_CHAIN":3}
        return sorted(out,key=lambda x:(x["url"],order.get(x["type"],9),x["evidence"]))
