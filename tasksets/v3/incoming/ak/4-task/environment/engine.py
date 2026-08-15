from dataclasses import dataclass,field
@dataclass(frozen=True)
class Packet: device:str;epoch:int;boot:int;seq:int;timestamp:int;sensor:str;value:int;mac:bytes
@dataclass(frozen=True)
class Token: token_id:str;issuer:str;subject:str;device:str;capabilities:int;not_after:int;parent:str;signature:bytes
@dataclass
class Device: device:str;boot:int;current_epoch:int;current_key:bytes;previous_key:bytes|None;previous_grace:int;ranges:dict[str,tuple[int,int]];telemetry_windows:dict=field(default_factory=dict);command_window:tuple[int,int]=(-1,0)
class GatewayError(ValueError):pass
class Gateway:
    def __init__(self,root_key:bytes,now:int,max_skew:int): raise NotImplementedError
    def provision(self,device:Device)->None: raise NotImplementedError
    def accept_telemetry(self,packet:Packet)->None: raise NotImplementedError
    def authorize(self,device:str,capability:int,nonce:int,chain:list[Token])->None: raise NotImplementedError
