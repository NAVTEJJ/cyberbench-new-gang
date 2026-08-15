import urllib.parse, unicodedata

HOP={"connection","keep-alive","proxy-authenticate","proxy-authorization","te","trailer","transfer-encoding","upgrade"}

class GatewayAnalyzer:
    def analyze(self, requests):
        out=[]
        for r in requests:
            rid=r.get("id","")
            pseudo=r.get("pseudo",[])
            headers=[(k.lower(),v) for k,v in r.get("headers",[])]
            origin=[(k.lower(),v) for k,v in r.get("origin_headers",[])]
            pnames=[k for k,v in pseudo if k.startswith(":")]
            vals=dict(pseudo)
            if len(pnames)!=len(set(pnames)) or any(not k.startswith(":") for k,v in pseudo[:len(pnames)]) or ":authority" not in pnames or str(vals.get(":path","")).startswith(("http://","https://")):
                out.append({"id":rid,"type":"PSEUDO_HEADER_CONFUSION","evidence":"misordered or absolute pseudo headers"})
            host=next((v for k,v in headers if k=="host"), vals.get(":authority"))
            if host and vals.get(":authority") and host!=vals.get(":authority"):
                if not any(x["id"]==rid and x["type"]=="PSEUDO_HEADER_CONFUSION" for x in out):
                    out.append({"id":rid,"type":"PSEUDO_HEADER_CONFUSION","evidence":"authority/host mismatch"})
            cls=[v for k,v in headers if k=="content-length"]
            if len(set(cls))>1 or (len(cls)>1) or any(k=="transfer-encoding" for k,v in headers) or r.get("body_len")!=r.get("downgraded_body_len",r.get("body_len")):
                out.append({"id":rid,"type":"H2_CL_TE_SMUGGLE","evidence":"duplicate content-length and transfer-encoding"})
            decoded=unicodedata.normalize("NFKC", urllib.parse.unquote(str(vals.get(":path",""))+"".join(v for k,v in headers)))
            if "\r" in decoded or "\n" in decoded:
                out.append({"id":rid,"type":"REQUEST_SPLIT","evidence":"decoded CRLF"})
            xfh=next((v for k,v in headers if k=="x-forwarded-host"),None)
            if xfh and r.get("origin_route")==xfh and xfh not in str(r.get("cache_key","")):
                out.append({"id":rid,"type":"CACHE_POISON","evidence":"x-forwarded-host routes origin outside cache key"})
            conn=[]
            for k,v in headers:
                if k=="connection": conn += [x.strip().lower() for x in v.split(",")]
            leaked=[k for k,v in origin if k in HOP or k in conn]
            if leaked:
                out.append({"id":rid,"type":"HOP_BY_HOP_LEAK","evidence":leaked[0]})
        order={"H2_CL_TE_SMUGGLE":0,"PSEUDO_HEADER_CONFUSION":1,"CACHE_POISON":2,"REQUEST_SPLIT":3,"HOP_BY_HOP_LEAK":4}
        return sorted(out,key=lambda x:(x["id"],order.get(x["type"],9),x["evidence"]))
