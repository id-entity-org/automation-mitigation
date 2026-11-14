import {test} from 'node:test';
import assert from 'node:assert/strict';

for(const test_ of [
  {name:'Test1 default',suffix:'',expected:'e3ea79c441ffad7039ec422e83eb952c5244373c3b1a577c2fec5ee439ff2563'},
  {name:'Test1 high memory',suffix:'-high-mem',expected:'457e2e6181d20c8e9146e6ddf0c434e0bd37b16175b4048241b55044514d50bc'},
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
  {name:'Test2 default',suffix:'',expected:'38b6f08cee97642705391cf09a28de604e37da732f80e0f8af9b9e2531157a88'},
  {name:'Test2 high memory',suffix:'-high-mem',expected:'5bd488a58a73d01eaea98bbd3c1a9da296c03159393e03a353936a82acdb664e'},
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
