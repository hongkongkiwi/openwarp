// Client half of the derived authentication protocol. The password, the
// wrapping key and the private key stay in this browser; the server receives
// only an authentication key and an AES-GCM-wrapped private key.
'use strict';
const AuthV2 = (() => {
  function b64dec(s) {
    const bin = atob(String(s).trim());
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function b64enc(bytes) {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function hex(bytes) { return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join(''); }
  async function deriveKeys(password, saltB64, iterations) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
    const bits = new Uint8Array(await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt: b64dec(saltB64), iterations: Number(iterations), hash: 'SHA-256' }, base, 512));
    const auth = bits.slice(0, 32);
    const wrap = await crypto.subtle.importKey('raw', bits.slice(32), 'AES-GCM', false, ['encrypt', 'decrypt']);
    return { auth, wrap };
  }
  async function proof(auth, challenge, challengeId) {
    const key = await crypto.subtle.importKey('raw', auth, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key,
      new TextEncoder().encode(challenge + '|' + challengeId)));
    return hex(sig);
  }
  async function wrapPrivate(wrap, secret) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrap, secret));
    const out = new Uint8Array(iv.length + ct.length);
    out.set(iv); out.set(ct, iv.length);
    return 'owv2:' + b64enc(out);
  }
  async function unwrapPrivate(wrap, wrapped) {
    if (!String(wrapped).startsWith('owv2:')) throw new Error('not an owv2 key');
    const raw = b64dec(wrapped.slice(5));
    if (raw.length < 13) throw new Error('wrapped key is too short');
    return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: raw.slice(0, 12) }, wrap, raw.slice(12)));
  }
  function randomSalt() { return b64enc(crypto.getRandomValues(new Uint8Array(16))); }
  async function kdf(email) {
    const r = await fetch('/api/auth/kdf?email=' + encodeURIComponent(email));
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Sign-in options could not be loaded');
    return d;
  }
  async function challenge(email) {
    const r = await fetch('/api/auth/challenge', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email }) });
    const d = await r.json();
    if (!r.ok) throw new Error(d.error || 'Sign-in could not start');
    return d;
  }
  return { b64dec, b64enc, deriveKeys, proof, wrapPrivate, unwrapPrivate, randomSalt, kdf, challenge };
})();
