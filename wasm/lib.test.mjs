import {test} from 'node:test';
import assert from 'node:assert/strict';

for(const test_ of [
  {name:'Test1 default',suffix:'',expected:'60232bc8fa20f574a491739bab53a9e3370f57b173193f7ece662735f6d0296e'},
  {name:'Test1 high memory',suffix:'-high-mem',expected:'25efbcf645919c0d3a1e75494a6f97c8e91aa57ac4d19625c782caa7d9f9065e'},
]){
  test(test_.name,async()=>{
    const nonce=new Uint8Array(16);
    nonce.setFromHex("0b206ed758abdcb0d43c9bb3e7808495");
    const {default:pow}=await import(`./dist/lib${test_.suffix}-min.mjs`);
    const abortController=new AbortController();
    const progress=[];
    const proof=await pow(nonce,abortController.signal,value=>progress.push(value));
    assert.equal(proof.buffer.byteLength,proof.byteLength);
    assert.equal(progress.at(-1),1);
    assert.ok(progress.every((value,i)=>value>=0&&value<=1&&(!i||value>=progress[i-1])));
    const hashBuffer=await crypto.subtle.digest('SHA-256',proof);
    const hash=new Uint8Array(hashBuffer).toHex();
    assert.equal(hash,test_.expected);
  });
}

test('abort when root search begins',async()=>{
  const {default:pow}=await import('./dist/lib-min.mjs');
  const controller=new AbortController();
  const pending=pow(new Uint8Array(16),controller.signal,progress=>{
    if(progress>=.75) controller.abort();
  });
  await assert.rejects(pending);
  assert.ok(controller.signal.aborted);
});

for(const test_ of [
  {name:'Test2 default',suffix:'',expected:'1cd4d20f292ecfd183ef090b71c716b1ced8986aff386cb5b8bc7c2e03acb9e1'},
  {name:'Test2 high memory',suffix:'-high-mem',expected:'ab076454f1fad6cfa4464425c36de0907e0e269071b9a7691cbd881bb8615ae0'},
]){
  test(test_.name,async()=>{
    const nonce=new Uint8Array(16);
    nonce.setFromHex("8b7df143d91c716ecfa5fc1730022f6b");
    const {default:pow}=await import(`./dist/lib${test_.suffix}-min.mjs`);
    const abortController=new AbortController();
    const proof=await pow(nonce,abortController.signal);
    assert.equal(proof.buffer.byteLength,proof.byteLength);
    const hashBuffer=await crypto.subtle.digest('SHA-256',proof);
    const hash=new Uint8Array(hashBuffer).toHex();
    assert.equal(hash,test_.expected);
  });
}
