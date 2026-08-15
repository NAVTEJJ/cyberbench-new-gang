from dataclasses import dataclass
import hashlib,re,unicodedata
class ResolveError(ValueError):pass
@dataclass(frozen=True)
class Artifact:name:str;version:str;path:str;digest:str;content:bytes;builder:str;dependencies:tuple[tuple[str,str],...];provenance:tuple[tuple[str,str],...]
@dataclass(frozen=True)
class Policy:trusted_builders:frozenset[str];allow_prerelease:bool=False
def normalize_path(path):
 p=unicodedata.normalize("NFC",path)
 if not p or p.startswith("/") or "\\" in p or re.search(r"%2f|%5c",p,re.I) or any(ord(c)<32 for c in p):raise ResolveError("path")
 parts=p.split("/")
 if any(x in ("",".","..") for x in parts):raise ResolveError("path")
 return "/".join(parts)
def _v(s):
 m=re.fullmatch(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z.-]+))?",s)
 if not m:raise ResolveError("version")
 pre=m.group(4);return(int(m.group(1)),int(m.group(2)),int(m.group(3)),(1,) if pre is None else (0,)+tuple((0,int(x)) if x.isdigit() else (1,x) for x in pre.split(".")))
def _ok(v,r):
 if r=="*":return True
 for x in r.split(","):
  x=x.strip()
  if x.startswith("^"):
   b=_v(x[1:]);return v>=b and v<(b[0]+1,0,0,(1,))
  if x.startswith("~"):
   b=_v(x[1:]);return v>=b and v<(b[0],b[1]+1,0,(1,))
  op=next((o for o in (">=","<=","!=","<",">","=") if x.startswith(o)),"=");b=_v(x[len(op):] if x.startswith(op) else x)
  if not {">=":v>=b,"<=":v<=b,"!=":v!=b,"<":v<b,">":v>b,"=":v==b}[op]:return False
 return True
def resolve(roots,candidates,cache,policy):
 by={};aliases={}
 for a in candidates:
  path=normalize_path(a.path);alias=path.casefold()
  if alias in aliases and aliases[alias]!=path:raise ResolveError("path-collision")
  aliases[alias]=path
  if hashlib.sha256(a.content).hexdigest()!=a.digest:continue
  by.setdefault(a.name,[]).append(a)
 req={};best=None
 def rec(selected,requirements):
  nonlocal best
  pending=next((n for n in sorted(requirements) if n not in selected),None)
  if pending is None:
   graph={n:[d for d,_ in a.dependencies] for n,a in selected.items()};state={}
   def dfs(n):
    if state.get(n)==1:raise ResolveError("cycle")
    if state.get(n)==2:return
    state[n]=1
    for d in graph[n]:dfs(d)
    state[n]=2
   for n in graph:dfs(n)
   trusted=all(a.builder in policy.trusted_builders and dict(a.provenance)=={d:selected[d].digest for d,_ in a.dependencies} for a in selected.values())
   misses=sum(cache.get(a.path)!=a.digest for a in selected.values())
   order=[]
   def topo(n):
    for d in graph[n]:
     if d not in order:topo(d)
    if n not in order:order.append(n)
   for n,_ in roots:topo(n)
   score=(not trusted,misses,tuple(_v(selected[n].version) for n,_ in roots),tuple(_v(selected[n].version) for n in sorted(selected)),tuple(selected[n].digest for n in sorted(selected)))
   if best is None or score<best[0]:best=(score,dict(selected),order)
   return
  for a in sorted(by.get(pending,[]),key=lambda x:(_v(x.version),x.digest),reverse=True):
   v=_v(a.version)
   if (not policy.allow_prerelease and v[3][0]==0) or not all(_ok(v,r) for r in requirements[pending]):continue
   nr={k:list(vs) for k,vs in requirements.items()}
   for d,r in a.dependencies:nr.setdefault(d,[]).append(r)
   rec({**selected,pending:a},nr)
 requirements={n:[r] for n,r in roots};rec({},requirements)
 if best is None:raise ResolveError("unsatisfiable")
 return [best[1][n] for n in best[2]],[best[1][n].path for n in best[2]]
