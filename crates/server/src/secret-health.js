/* Local advisory checks. Password range lookups require explicit opt-in. */
(function(root) {
  'use strict';
  const commonJS = typeof module === 'object' && module.exports;
  const estimator = commonJS ? require('./vendor/zxcvbn.js') : root.zxcvbn;
  const crypto = commonJS ? require('node:crypto').webcrypto : root.crypto;
  function valid(value) { return typeof value === 'string' && value.length > 0 && value.length <= 1024; }
  function localStrength(value) {
    if (!valid(value) || typeof estimator !== 'function') return { status: 'unavailable' };
    return { score: estimator(value).score };
  }
  async function checkPassword(value, options = {}) {
    if (options.enabled !== true) return { status: 'disabled' };
    if (!valid(value)) return { status: 'unavailable' };
    const controller = new AbortController();
    let timer;
    try {
      return await Promise.race([(async () => {
        const digest = await crypto.subtle.digest('SHA-1', new TextEncoder().encode(value));
        const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        const response = await (options.fetch || root.fetch)(`https://api.pwnedpasswords.com/range/${hash.slice(0, 5)}`, {
          headers: { 'Add-Padding': 'true' }, credentials: 'omit', referrerPolicy: 'no-referrer', redirect: 'error', signal: controller.signal
        });
        if (!response.ok || !response.body?.getReader) throw new Error('unavailable');
        const reader = response.body.getReader(), chunks = [];
        let size = 0;
        try {
          while (true) {
            const { done, value: chunk } = await reader.read();
            if (done) break;
            size += chunk.byteLength;
            if (size > 1024 * 1024) throw new Error('oversized');
            chunks.push(chunk);
          }
        } catch (e) { await reader.cancel().catch(() => {}); throw e; }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
        const rows = text.replace(/\r?\n$/, '').split(/\r?\n/);
        let count = 0;
        for (const row of rows) {
          const match = /^([A-F0-9]{35}):([0-9]+)$/.exec(row);
          if (!match || !Number.isSafeInteger(Number(match[2]))) throw new Error('malformed');
          if (match[1] === hash.slice(5)) count = Number(match[2]);
        }
        return count > 0 ? { status: 'found', count } : { status: 'not_found' };
      })(), new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('timeout')); }, 10000); })]);
    } catch (_) { return { status: 'unavailable' }; }
    finally { clearTimeout(timer); controller.abort(); }
  }
  async function checkEnzoicPassword(value, options = {}) {
    if (options.enabled !== true) return { status: 'disabled' };
    if (!valid(value)) return { status: 'unavailable' };
    const controller = new AbortController();
    let timer;
    try {
      return await Promise.race([(async () => {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
        const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
        const response = await (options.fetch || root.fetch)('/api/me/secret-health/enzoic/password', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ prefix: hash.slice(0, 10), consent: true }),
          credentials: 'same-origin', referrerPolicy: 'no-referrer', redirect: 'error', signal: controller.signal
        });
        if (!response.ok || !response.body?.getReader) throw new Error('unavailable');
        const reader = response.body.getReader(), chunks = [];
        let size = 0;
        try {
          while (true) {
            const { done, value: chunk } = await reader.read();
            if (done) break;
            size += chunk.byteLength;
            if (size > 1024 * 1024) throw new Error('oversized');
            chunks.push(chunk);
          }
        } catch (e) { await reader.cancel().catch(() => {}); throw e; }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        if (!data || !Array.isArray(data.candidates) || data.candidates.length > 1000) throw new Error('malformed');
        let found = false, count = 0;
        for (const row of data.candidates) {
          if (!row || typeof row.sha256 !== 'string' || !/^[a-f0-9]{64}$/i.test(row.sha256) ||
              typeof row.revealedInExposure !== 'boolean' || !Number.isSafeInteger(row.exposureCount) || row.exposureCount < 0) throw new Error('malformed');
          if (row.sha256.toLowerCase() === hash && row.revealedInExposure) { found = true; count = row.exposureCount; }
        }
        return found ? { status: 'found', count } : { status: 'not_found' };
      })(), new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('timeout')); }, 10000); })]);
    } catch (_) { return { status: 'unavailable' }; }
    finally { clearTimeout(timer); controller.abort(); }
  }
  async function checkEmailExposure(value, options = {}) {
    if (options.enabled !== true) return { status: 'disabled' };
    if (typeof value !== 'string' || value.length > 254 || /[\r\n\x00-\x1f\x7f]/.test(value)) return { status: 'unavailable' };
    const email = value.trim().toLowerCase();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) || new TextEncoder().encode(email).length > 254) return { status: 'unavailable' };
    const controller = new AbortController();
    let timer;
    try {
      return await Promise.race([(async () => {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(email));
        const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
        const response = await (options.fetch || root.fetch)('/api/me/secret-health/leakcheck', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email_hash: hash.slice(0, 24), consent: true }),
          credentials: 'same-origin', referrerPolicy: 'no-referrer', redirect: 'error', signal: controller.signal
        });
        if (!response.ok || !response.body?.getReader) throw new Error('unavailable');
        const reader = response.body.getReader(), chunks = [];
        let size = 0;
        try {
          while (true) {
            const { done, value: chunk } = await reader.read();
            if (done) break;
            size += chunk.byteLength;
            if (size > 65536) throw new Error('oversized');
            chunks.push(chunk);
          }
        } catch (e) { await reader.cancel().catch(() => {}); throw e; }
        const bytes = new Uint8Array(size); let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        const data = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
        if (!data || !Array.isArray(data.breaches) || data.breaches.length > 1000 ||
            !['found', 'not_found'].includes(data.status) || (data.status === 'found') !== (data.breaches.length > 0)) throw new Error('malformed');
        const breaches = [];
        for (const name of data.breaches) {
          if (typeof name !== 'string' || !name.trim() || name.length > 128 || /[\x00-\x1f\x7f]/.test(name)) throw new Error('malformed');
          breaches.push(name);
        }
        return { status: data.status, breaches };
      })(), new Promise((_, reject) => { timer = setTimeout(() => { controller.abort(); reject(new Error('timeout')); }, 10000); })]);
    } catch (_) { return { status: 'unavailable' }; }
    finally { clearTimeout(timer); controller.abort(); }
  }
  const api = { localStrength, checkPassword, checkEnzoicPassword, checkEmailExposure };
  if (commonJS) module.exports = api;
  else root.OpenWarpSecretHealth = api;
})(typeof globalThis !== 'undefined' ? globalThis : this);
