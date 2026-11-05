// OpenWarp browser E2E crypto: X25519 + XChaCha20-Poly1305, wire-compatible
// with openwarp-crypto. Private keys never leave the browser.
'use strict';
const OW = (() => {
  const b64dec = (s) => Uint8Array.from(atob(s.trim()), c => c.charCodeAt(0));
  const b64enc = (b) => btoa(String.fromCharCode(...b));
  // ---- X25519 (BigInt) ----
  const P = (1n << 255n) - 19n;
  const mod = (a) => ((a % P) + P) % P;
  const pow = (a, e) => { let r = 1n; a = mod(a); while (e) { if (e & 1n) r = mod(r * a); a = mod(a * a); e >>= 1n; } return r; };
  const leToInt = (b) => { let n = 0n; for (let i = b.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(b[i]); return n; };
  const intToLe = (n, len = 32) => { const b = new Uint8Array(len); for (let i = 0; i < len; i++) { b[i] = Number(n & 255n); n >>= 8n; } return b; };
  function x25519(secret, pub) {
    const k = Uint8Array.from(secret); k[0] &= 248; k[31] &= 127; k[31] |= 64;
    const scalar = leToInt(k); const x1 = mod(leToInt(pub) & ((1n << 255n) - 1n));
    let x2 = 1n, z2 = 0n, x3 = x1, z3 = 1n, swap = 0n;
    const a24 = 121665n;
    for (let t = 254; t >= 0; t--) {
      const kt = (scalar >> BigInt(t)) & 1n; swap ^= kt;
      if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; } swap = kt;
      const A = mod(x2 + z2), AA = mod(A * A), B = mod(x2 - z2), BB = mod(B * B);
      const E = mod(AA - BB), C = mod(x3 + z3), D = mod(x3 - z3);
      const DA = mod(D * A), CB = mod(C * B);
      x3 = mod((DA + CB) * (DA + CB)); z3 = mod(x1 * mod((DA - CB) * (DA - CB)));
      x2 = mod(AA * BB); z2 = mod(E * mod(AA + mod(a24 * E)));
    }
    if (swap) { [x2, x3] = [x3, x2]; [z2, z3] = [z3, z2]; }
    return intToLe(mod(x2 * pow(z2, P - 2n)));
  }
  const x25519Pub = (secret) => { const base = new Uint8Array(32); base[0] = 9; return x25519(secret, base); };
  // ---- ChaCha ----
  const rotl = (v, c) => (v << c) | (v >>> (32 - c));
  function qr(s, a, b, c, d) { s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 16); s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 12); s[a] = (s[a] + s[b]) | 0; s[d] = rotl(s[d] ^ s[a], 8); s[c] = (s[c] + s[d]) | 0; s[b] = rotl(s[b] ^ s[c], 7); }
  const u32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
  const putU32 = (b, o, v) => { b[o] = v; b[o + 1] = v >> 8; b[o + 2] = v >> 16; b[o + 3] = v >> 24; };
  function chachaBlock(key, nonce12, counter) {
    const st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    for (let i = 0; i < 8; i++) st.push(u32(key, i * 4));
    st.push(counter); for (let i = 0; i < 3; i++) st.push(u32(nonce12, i * 4));
    const w = st.slice();
    for (let i = 0; i < 10; i++) { qr(w,0,4,8,12); qr(w,1,5,9,13); qr(w,2,6,10,14); qr(w,3,7,11,15); qr(w,0,5,10,15); qr(w,1,6,11,12); qr(w,2,7,8,13); qr(w,3,4,9,14); }
    const out = new Uint8Array(64); for (let i = 0; i < 16; i++) putU32(out, i * 4, (w[i] + st[i]) | 0); return out;
  }
  function hchacha(key, nonce16) {
    const st = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    for (let i = 0; i < 8; i++) st.push(u32(key, i * 4)); for (let i = 0; i < 4; i++) st.push(u32(nonce16, i * 4));
    for (let i = 0; i < 10; i++) { qr(st,0,4,8,12); qr(st,1,5,9,13); qr(st,2,6,10,14); qr(st,3,7,11,15); qr(st,0,5,10,15); qr(st,1,6,11,12); qr(st,2,7,8,13); qr(st,3,4,9,14); }
    const out = new Uint8Array(32); [0,1,2,3,12,13,14,15].forEach((s, i) => putU32(out, i * 4, st[s])); return out;
  }
  function chachaStream(key, nonce12, data, counterStart) {
    const out = new Uint8Array(data.length); let counter = counterStart;
    for (let off = 0; off < data.length; off += 64) { const block = chachaBlock(key, nonce12, counter++); const n = Math.min(64, data.length - off); for (let i = 0; i < n; i++) out[off + i] = data[off + i] ^ block[i]; }
    return out;
  }
  // ---- Poly1305 ----
  const P1305 = (1n << 130n) - 5n;
  function poly1305(msg, key32) {
    const rBytes = Uint8Array.from(key32.slice(0, 16)); rBytes[3] &= 15; rBytes[7] &= 15; rBytes[11] &= 15; rBytes[15] &= 15; rBytes[4] &= 252; rBytes[8] &= 252; rBytes[12] &= 252;
    const r = leToInt(rBytes), s = leToInt(key32.slice(16, 32)); let acc = 0n;
    for (let off = 0; off < msg.length; off += 16) { const chunk = msg.slice(off, off + 16); const n = leToInt(chunk) + (1n << BigInt(8 * chunk.length)); acc = mod1305((acc + n) * r); }
    function mod1305(a) { return ((a % P1305) + P1305) % P1305; }
    const tag = (acc + s) % (1n << 128n); return intToLe(tag, 16);
  }
  function aeadTag(polyKey, ct) {
    const parts = []; parts.push(ct); const pad = (16 - (ct.length % 16)) % 16; parts.push(new Uint8Array(pad));
    const lens = new Uint8Array(16); putU32(lens, 0, 0); putU32(lens, 8, ct.length);
    parts.push(lens); const total = parts.reduce((a, p) => a + p.length, 0); const msg = new Uint8Array(total); let o = 0; for (const p of parts) { msg.set(p, o); o += p.length; } return poly1305(msg, polyKey);
  }
  function xchachaEncrypt(key, nonce24, plaintext) {
    const sub = hchacha(key, nonce24.slice(0, 16)); const nonce12 = new Uint8Array(12); nonce12.set(nonce24.slice(16, 24), 4);
    const polyKey = chachaBlock(sub, nonce12, 0).slice(0, 32);
    const ct = chachaStream(sub, nonce12, plaintext, 1); const tag = aeadTag(polyKey, ct);
    const out = new Uint8Array(ct.length + 16); out.set(ct); out.set(tag, ct.length); return out;
  }
  function xchachaDecrypt(key, nonce24, ctAndTag) {
    if (ctAndTag.length < 16) throw new Error('ciphertext too short');
    const ct = ctAndTag.slice(0, ctAndTag.length - 16), tag = ctAndTag.slice(ctAndTag.length - 16);
    const sub = hchacha(key, nonce24.slice(0, 16)); const nonce12 = new Uint8Array(12); nonce12.set(nonce24.slice(16, 24), 4);
    const polyKey = chachaBlock(sub, nonce12, 0).slice(0, 32); const expect = aeadTag(polyKey, ct);
    let diff = 0; for (let i = 0; i < 16; i++) diff |= expect[i] ^ tag[i]; if (diff) throw new Error('decrypt failed (wrong key or tampered)');
    return chachaStream(sub, nonce12, ct, 1);
  }
  // ---- OpenWarp formats ----
  async function sha256(data) { const h = await crypto.subtle.digest('SHA-256', data); return new Uint8Array(h); }
  async function sessionKey(shared) { const prefix = new TextEncoder().encode('openwarp-session-v1'); const buf = new Uint8Array(prefix.length + 32); buf.set(prefix); buf.set(shared, prefix.length); return sha256(buf); }
  async function decryptAsymmetric(privB64, payloadB64) {
    const raw = b64dec(payloadB64); const ephPub = raw.slice(0, 32), nonce = raw.slice(32, 56), ct = raw.slice(56);
    const shared = x25519(b64dec(privB64), ephPub); const key = await sessionKey(shared);
    return xchachaDecrypt(key, nonce, ct);
  }
  async function encryptAsymmetric(pubB64, plaintext) {
    const ephSecret = crypto.getRandomValues(new Uint8Array(32)); const ephPub = x25519Pub(ephSecret);
    const shared = x25519(ephSecret, b64dec(pubB64)); const key = await sessionKey(shared);
    const nonce = crypto.getRandomValues(new Uint8Array(24)); const ct = xchachaEncrypt(key, nonce, plaintext);
    const out = new Uint8Array(32 + 24 + ct.length); out.set(ephPub); out.set(nonce, 32); out.set(ct, 56); return b64enc(out);
  }
  function decryptSymmetric(keyBytes, payloadB64) { const raw = b64dec(payloadB64); return xchachaDecrypt(keyBytes, raw.slice(0, 24), raw.slice(24)); }
  function encryptSymmetric(keyBytes, plaintext) { const nonce = crypto.getRandomValues(new Uint8Array(24)); const ct = xchachaEncrypt(keyBytes, nonce, plaintext); const out = new Uint8Array(24 + ct.length); out.set(nonce); out.set(ct, 24); return b64enc(out); }
  return { b64dec, b64enc, x25519, x25519Pub, decryptAsymmetric, encryptAsymmetric, decryptSymmetric, encryptSymmetric, _xchachaEncrypt: xchachaEncrypt, _xchachaDecrypt: xchachaDecrypt };
})();
if (typeof module !== 'undefined') module.exports = OW;
