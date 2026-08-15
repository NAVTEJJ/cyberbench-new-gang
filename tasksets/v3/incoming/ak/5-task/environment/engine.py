from dataclasses import dataclass
class ResolveError(ValueError):pass
@dataclass(frozen=True)
class Artifact:
 name:str;version:str;path:str;digest:str;content:bytes;builder:str
 dependencies:tuple[tuple[str,str],...];provenance:tuple[tuple[str,str],...]
@dataclass(frozen=True)
class Policy:trusted_builders:frozenset[str];allow_prerelease:bool=False
def normalize_path(path:str)->str:raise NotImplementedError
def resolve(roots:tuple[tuple[str,str],...],candidates:list[Artifact],cache:dict[str,str],policy:Policy)->tuple[list[Artifact],list[str]]:
    raise NotImplementedError
