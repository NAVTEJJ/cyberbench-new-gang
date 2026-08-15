from dataclasses import dataclass,field
import hashlib,hmac,struct
@dataclass(frozen=True)
class Packet:device:str;epoch:int;boot:int;seq:int;timestamp:int;sensor:str;value:int;mac:bytes
@dataclass(frozen=True)
class Token:token_id:str;issuer:str;subject:str;device:str;capabilities:int;not_after:int;parent:str;signature:bytes
@dataclass
class Device:device:str;boot:int;current_epoch:int;current_key:bytes;previous_key:bytes|None;previous_grace:int;ranges:dict[str,tuple[int,int]];telemetry_windows:dict=field(default_factory=dict);command_window:tuple[int,int]=(-1,0)
class GatewayError(ValueError):pass
def _window(state,n,width):
 hi,bits=state
 if n<0:return None
 if hi<0:return(n,1)
 if n>hi:
  shift=n-hi;return(n,1 if shift>width else ((bits<<shift)|1)&((1<<(width+1))-1))
 d=hi-n
 if d>width or bits>>d&1:return None
 return hi,bits|(1<<d)
def _enc(*xs):return b"\0".join(str(x).encode() for x in xs)
class Gateway:
 def __init__(self,root_key,now,max_skew):self.root_key=root_key;self.now=now;self.max_skew=max_skew;self.devices={}
 def provision(self,d):
  if d.device in self.devices:raise GatewayError("duplicate")
  self.devices[d.device]=d
 def accept_telemetry(self,p):
  d=self.devices.get(p.device)
  if not d or p.boot!=d.boot or abs(p.timestamp-self.now)>self.max_skew:raise GatewayError("device-or-time")
  key=d.current_key if p.epoch==d.current_epoch else d.previous_key if p.epoch==d.current_epoch-1 and self.now<=d.previous_grace else None
  if key is None or p.sensor not in d.ranges or not d.ranges[p.sensor][0]<=p.value<=d.ranges[p.sensor][1]:raise GatewayError("epoch-or-range")
  raw=_enc(p.device,p.epoch,p.boot,p.seq,p.timestamp,p.sensor,p.value)
  if not hmac.compare_digest(p.mac,hmac.new(key,raw,hashlib.sha256).digest()):raise GatewayError("mac")
  k=(p.epoch,p.boot);nw=_window(d.telemetry_windows.get(k,(-1,0)),p.seq,128)
  if nw is None:raise GatewayError("replay")
  d.telemetry_windows[k]=nw
 def authorize(self,device,capability,nonce,chain):
  d=self.devices.get(device)
  if not d or not chain or capability<=0:raise GatewayError("bad-command")
  key=self.root_key;issuer="gateway";parent="";seen=set()
  for t in chain:
   if t.token_id in seen or t.issuer!=issuer or t.parent!=parent or t.device!=device or t.not_after<self.now:raise GatewayError("chain")
   raw=_enc(t.token_id,t.issuer,t.subject,t.device,t.capabilities,t.not_after,t.parent)
   if not hmac.compare_digest(t.signature,hmac.new(key,raw,hashlib.sha256).digest()):raise GatewayError("signature")
   if parent and t.capabilities|chain[chain.index(t)-1].capabilities!=chain[chain.index(t)-1].capabilities:raise GatewayError("amplification")
   seen.add(t.token_id);issuer=t.subject;parent=t.token_id;key=hashlib.sha256(t.signature).digest()
  if chain[-1].capabilities&capability!=capability:raise GatewayError("capability")
  nw=_window(d.command_window,nonce,64)
  if nw is None:raise GatewayError("replay")
  d.command_window=nw
