(function(root) {
  'use strict';
  const supported = new Set([1,2,3,13,14,19,25,27,32,35,37,40]);
  const salted = new Set([13,19,25,32,37,40]);
  const hex = (value, length) => typeof value === 'string' && value.length === length && /^[a-f0-9]+$/.test(value);
  const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
  const plainSalt = value => typeof value === 'string' && new TextEncoder().encode(value).length <= 1024 && !/^(?:\$argon2|base64:|hex:)/i.test(value);
  const encoding = value => value === undefined || value === 'plain';
  function library() {
    return typeof module === 'object' && module.exports ? require('./vendor/hash-wasm.js') : root.hashwasm;
  }
  async function hashPassword(algorithm, value) { return library()[algorithm](value); }
  async function argon2(options) { return library().argon2d(options); }
  async function checkCredentials(email, password, options = {}) {
    if (options.enabled !== true) return {status:'disabled'};
    if (typeof email !== 'string' || !email.length || email.length > 254 || typeof password !== 'string' || !password.length || password.length > 1024) return {status:'unavailable'};
    const guard = () => { if (options.isCurrent && !options.isCurrent()) throw new Error('cancelled'); };
    const digest = async (algorithm, value) => {
      guard();
      const result = await (options.hashPassword || hashPassword)(algorithm, value);
      if (!hex(result, {md5:32,sha1:40,sha256:64,sha384:96,sha512:128}[algorithm])) throw new Error('invalid digest');
      return result;
    };
    const request = async (stage, body) => {
      guard();
      const controller = new AbortController();
      let timer;
      try {
        return await Promise.race([(async () => {
          const response = await (options.fetch || root.fetch)(`/api/me/secret-health/enzoic/${stage}`, {
            method:'POST', credentials:'same-origin', redirect:'error', referrerPolicy:'no-referrer', signal:controller.signal,
            headers:{'Content-Type':'application/json'}, body:JSON.stringify({...body,consent:true})
          });
          if (!response.ok || !response.body?.getReader) throw new Error('relay unavailable');
          const reader = response.body.getReader(), chunks = [];
          let size = 0;
          try {
            while (true) {
              const {done,value} = await reader.read();
              if (done) break;
              size += value.byteLength;
              if (size > 1024 * 1024) throw new Error('response too large');
              chunks.push(value);
            }
          } catch (error) { await reader.cancel().catch(() => {}); throw error; }
          const bytes = new Uint8Array(size);
          let offset = 0;
          for (const chunk of chunks) { bytes.set(chunk,offset); offset += chunk.byteLength; }
          return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
        })(), new Promise((_,reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('timeout')); },10000); })]);
      } finally { clearTimeout(timer); controller.abort(); }
    };
    try {
      guard();
      const username = email.toLowerCase();
      const bytes = await root.crypto.subtle.digest('SHA-256', new TextEncoder().encode(username));
      const usernameHash = Array.from(new Uint8Array(bytes), b => b.toString(16).padStart(2,'0')).join('');
      const account = await request('accounts', {username_hash:usernameHash});
      guard();
      if (!object(account) || typeof account.found !== 'boolean') throw new Error('invalid account');
      if (!account.found) return {status:'not_found'};
      const requirements = account.passwordHashesRequired;
      if (!plainSalt(account.salt) || !encoding(account.saltEncoding) || !Array.isArray(requirements) || !requirements.length || requirements.length > 32) throw new Error('unsupported requirements');
      // Validate the complete set before doing any password work. Skipping one can hide a match.
      for (const spec of requirements) {
        if (!object(spec) || !supported.has(spec.hashType) || !encoding(spec.saltEncoding) || (spec.salt !== undefined && !plainSalt(spec.salt)) || (salted.has(spec.hashType) && (!plainSalt(spec.salt) || !spec.salt.length))) throw new Error('unsupported requirements');
      }
      const hashes = [];
      for (const spec of requirements) {
        const s = spec.salt;
        let legacy;
        switch (spec.hashType) {
          case 1: legacy = await digest('md5',password); break;
          case 2: legacy = await digest('sha1',password); break;
          case 3: legacy = await digest('sha256',password); break;
          case 13: legacy = await digest('md5',password+s); break;
          case 14: legacy = await digest('sha512',password); break;
          case 19: legacy = await digest('md5',s+password); break;
          case 25: legacy = await digest('sha1',password+s); break;
          case 27: legacy = await digest('md5',await digest('md5',password)); break;
          case 32: legacy = await digest('sha1',s+password); break;
          case 35: legacy = await digest('sha384',password); break;
          case 37: legacy = await digest('sha256',s+password); break;
          case 40: legacy = await digest('sha512',password+':'+s); break;
        }
        guard();
        const hash = await (options.argon2 || argon2)({password:username+'$'+legacy,salt:account.salt,type:'argon2d',iterations:3,memorySize:1024,parallelism:2,hashLength:20,outputType:'hex'});
        if (!hex(hash,40)) throw new Error('invalid derivation');
        hashes.push(hash);
      }
      const result = await request('credentials', {partial_hashes:[...new Set(hashes.map(h => h.slice(0,10)))]});
      if (!object(result) || !Array.isArray(result.candidateHashes) || result.candidateHashes.length > 1000 || !result.candidateHashes.every(h => hex(h,40))) throw new Error('invalid candidates');
      guard();
      return {status:result.candidateHashes.some(h => hashes.includes(h)) ? 'found' : 'not_found'};
    } catch (_) { return {status:'unavailable'}; }
  }
  const api = {checkCredentials,hashPassword,argon2};
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.OpenWarpEnzoicPairs = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
