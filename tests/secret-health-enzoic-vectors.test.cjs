'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const {createHash} = require('node:crypto');
const pairs = require('../crates/server/src/enzoic-pairs.js');
const wasm = require('../crates/server/src/vendor/hash-wasm.js');

for (const algorithm of ['md5','sha1','sha256','sha384','sha512']) {
  test(`real vendored ${algorithm} matches independent Node crypto`, async () => {
    for (const value of ['password','  e\u0301-\ud83d\udd10  ','']) {
      assert.equal(await pairs.hashPassword(algorithm,value),createHash(algorithm).update(value,'utf8').digest('hex'));
    }
  });
}
const vector = '58d8e72dbf85d3a2ec58967fe9a00ecda4aab6a7';
// Native reference CLI: printf %s 'fixture@example.invalid$5f4dcc3b5aa765d61d8327deb882cf99' | argon2 fixture-account-salt -d -t 3 -k 1024 -p 2 -l 20 -r -v 13
const options = {password:'fixture@example.invalid$5f4dcc3b5aa765d61d8327deb882cf99',salt:'fixture-account-salt',type:'argon2d',iterations:3,memorySize:1024,parallelism:2,hashLength:20,outputType:'hex'};
test('real vendored Argon2d matches independent native reference vector', async () => {
  assert.equal(await pairs.argon2({...options}),vector);
  assert.notEqual(await wasm.argon2id({...options}),vector);
});
test('default real primitives perform the pair protocol end to end without provider access', async () => {
  const requests = [];
  const result = await pairs.checkCredentials('FiXtUrE@Example.Invalid','password',{enabled:true,fetch:async (url,request) => {
    requests.push({url,body:JSON.parse(request.body)});
    return new Response(JSON.stringify(requests.length === 1 ? {found:true,salt:'fixture-account-salt',passwordHashesRequired:[{hashType:1}]} : {candidateHashes:[vector]}));
  }});
  assert.deepEqual(result,{status:'found'});
  assert.deepEqual(requests[1].body,{partial_hashes:[vector.slice(0,10)],consent:true});
});
test('generation invalidation after a digest prevents remaining hashing and stage two', async () => {
  let current = true, calls = 0, hashes = 0, derivations = 0;
  const result = await pairs.checkCredentials('fixture@example.invalid','password',{enabled:true,isCurrent:()=>current,
    fetch:async()=>{calls++;return new Response(JSON.stringify({found:true,salt:'fixture-account-salt',passwordHashesRequired:[{hashType:27}]}));},
    hashPassword:async()=>{hashes++;current=false;return 'a'.repeat(32);},argon2:async()=>{derivations++;return vector;}});
  assert.deepEqual(result,{status:'unavailable'});
  assert.equal(calls,1);assert.equal(hashes,1);assert.equal(derivations,0);
});
