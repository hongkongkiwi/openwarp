// OpenWarp browser E2E crypto: X25519 + XChaCha20-Poly1305 through libsodium,
// wire-compatible with openwarp-crypto. Private keys never leave the browser.
'use strict';
const OW = (() => {
  const b64dec = (s) => Uint8Array.from(atob(String(s).trim()), c => c.charCodeAt(0));
  const b64enc = (b) => { let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]); return btoa(s); };
  function S() { if (typeof sodium === 'undefined') throw new Error('libsodium is not loaded'); return sodium; }
  function cat(a, b) { const out = new Uint8Array(a.length + b.length); out.set(a); out.set(b, a.length); return out; }
  async function sessionKey(shared) { const prefix = new TextEncoder().encode('openwarp-session-v1'); return new Uint8Array(await crypto.subtle.digest('SHA-256', cat(prefix, shared))); }
  function x25519(secret, pub) { return S().crypto_scalarmult(secret, pub); }
  function x25519Pub(secret) { return S().crypto_scalarmult_base(secret); }
  async function decryptAsymmetric(privB64, payloadB64) {
    const s = S(); await s.ready;
    const raw = b64dec(payloadB64); if (raw.length < 56) throw new Error('ciphertext too short');
    const ephPub = raw.slice(0, 32), nonce = raw.slice(32, 56), ct = raw.slice(56);
    const key = await sessionKey(s.crypto_scalarmult(b64dec(privB64), ephPub));
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, key);
  }
  async function encryptAsymmetric(pubB64, plaintext) {
    const s = S(); await s.ready;
    const eph = s.crypto_box_keypair(); const nonce = s.randombytes_buf(24);
    const key = await sessionKey(s.crypto_scalarmult(eph.privateKey, b64dec(pubB64)));
    const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key);
    return b64enc(cat(cat(eph.publicKey, nonce), ct));
  }
  async function decryptSymmetric(keyBytes, payloadB64) {
    const s = S(); await s.ready;
    const raw = b64dec(payloadB64); if (raw.length < 24) throw new Error('ciphertext too short');
    return s.crypto_aead_xchacha20poly1305_ietf_decrypt(null, raw.slice(24), null, raw.slice(0, 24), keyBytes);
  }
  async function encryptSymmetric(keyBytes, plaintext) {
    const s = S(); await s.ready;
    const nonce = s.randombytes_buf(24);
    const ct = s.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, keyBytes);
    return b64enc(cat(nonce, ct));
  }
  async function generateKeypair() {
    const s = S(); await s.ready;
    const secret = s.randombytes_buf(32);
    return { secret, public: b64enc(s.crypto_scalarmult_base(secret)) };
  }
  function _xchachaEncrypt(key, nonce, plaintext) { return S().crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, null, null, nonce, key); }
  function _xchachaDecrypt(key, nonce, ct) { return S().crypto_aead_xchacha20poly1305_ietf_decrypt(null, ct, null, nonce, key); }
  return { b64dec, b64enc, x25519, x25519Pub, generateKeypair, decryptAsymmetric, encryptAsymmetric, decryptSymmetric, encryptSymmetric, _xchachaEncrypt, _xchachaDecrypt };
})();
if (typeof module !== 'undefined') module.exports = OW;
