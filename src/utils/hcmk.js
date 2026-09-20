// src/utils/hcmk.js
// SHA-256 Hash Chain & Merkle Tree Engine

const K = new Uint32Array([
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
]);

const enc = s => new TextEncoder().encode(s);
export const CHAIN_TAG = enc('hcmk-chain-v1');

const rotr = (a, n) => (a >>> n) | (a << (32 - n));

export const join = (...parts) => {
  const a = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let o = 0; for (const p of parts) { a.set(p, o); o += p.length; } return a;
};

export function H(...parts) {
  const msg = join(...parts), n = Math.ceil((msg.length + 9) / 64) * 64, buf = new Uint8Array(n);
  buf.set(msg); buf[msg.length] = 128;
  const dv = new DataView(buf.buffer);
  dv.setUint32(n - 4, msg.length * 8, false);
  const st = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), w = new Uint32Array(64);
  for (let o = 0; o < n; o += 64) {
    for (let t = 0; t < 16; t++) w[t] = dv.getUint32(o + t * 4, false);
    for (let t = 16; t < 64; t++) { const a = w[t-15], b = w[t-2]; w[t] = (w[t-16] + (rotr(a,7)^rotr(a,18)^(a>>>3)) + w[t-7] + (rotr(b,17)^rotr(b,19)^(b>>>10))) >>> 0; }
    let [a,b,c,d,e,f,g,h] = st;
    for (let t = 0; t < 64; t++) {
      const T1 = (h + (rotr(e,6)^rotr(e,11)^rotr(e,25)) + ((e&f)^((~e)&g)) + K[t] + w[t]) >>> 0;
      const T2 = ((rotr(a,2)^rotr(a,13)^rotr(a,22)) + ((a&b)^(a&c)^(b&c))) >>> 0;
      h = g; g = f; f = e; e = (d + T1) >>> 0; d = c; c = b; b = a; a = (T1 + T2) >>> 0;
    }
    st[0] = (st[0]+a)>>>0; st[1] = (st[1]+b)>>>0; st[2] = (st[2]+c)>>>0; st[3] = (st[3]+d)>>>0;
    st[4] = (st[4]+e)>>>0; st[5] = (st[5]+f)>>>0; st[6] = (st[6]+g)>>>0; st[7] = (st[7]+h)>>>0;
  }
  const res = new Uint8Array(32), rdv = new DataView(res.buffer);
  for (let i = 0; i < 8; i++) rdv.setUint32(i * 4, st[i], false);
  return res;
}

export function indexBytes(i) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, i, false);
  return b;
}

export function at(arr, idx) {
  return arr.subarray(idx * 32, (idx + 1) * 32);
}

export function hex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function short(bytes, len = 8) {
  if (!bytes) return '';
  const h = hex(bytes);
  return h.slice(0, len) + '…' + h.slice(-len);
}

export function sub(i) {
  const subs = ['₀','₁','₂','₃','₄','₅','₆','₇','₈','₉'];
  return String(i).split('').map(d => subs[parseInt(d, 10)] || d).join('');
}

export function randomSeed() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return bytes;
}
