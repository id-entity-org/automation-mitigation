import {strictEqual, rejects, deepStrictEqual} from 'node:assert';
import pow from './lib.mjs';

Deno.test('rejects invalid nonces and already aborted requests', async()=>{
  await rejects(pow(new Uint8Array(15)), TypeError);
  await rejects(pow(new Uint8Array(17)), TypeError);
  await rejects(pow(Array(16).fill(0)), TypeError);
  const controller=new AbortController();
  controller.abort(new Error('cancelled'));
  await rejects(pow(new Uint8Array(16),controller.signal), /cancelled/);
});

Deno.test('abort during worker startup rejects and removes the listener', async()=>{
  const controller=new AbortController();
  let listeners=0;
  const add=controller.signal.addEventListener.bind(controller.signal);
  const remove=controller.signal.removeEventListener.bind(controller.signal);
  controller.signal.addEventListener=(...args)=>{listeners++;return add(...args);};
  controller.signal.removeEventListener=(...args)=>{listeners--;return remove(...args);};
  const pending=pow(new Uint8Array(16),controller.signal);
  const timer=setTimeout(()=>controller.abort(new Error('startup cancelled')),10);
  try { await rejects(pending,/startup cancelled/); }
  finally { clearTimeout(timer); }
  strictEqual(listeners,0);
});

Deno.test('chain worker serves reference block zero', async()=>{
  const worker=new Worker(new URL('./lib-min.mjs',import.meta.url),{type:'module',name:'test-1'});
  const channel=new MessageChannel();
  let timer;
  try {
    await new Promise((resolve,reject)=>{
      timer=setTimeout(()=>reject(new Error('worker timed out')),30000);
      worker.onerror=event=>reject(new Error(event.message));
      let generated=false;
      channel.port1.onmessage=({data})=>{
        if(!generated){
          generated=true;
          worker.postMessage({hash:'test',index:0});
        }else{
          try { deepStrictEqual(data,new Uint8Array(256)); resolve(); }
          catch(error) { reject(error); }
        }
      };
      worker.onmessage=({data})=>{
        if(data.ready) worker.postMessage({hash:'test',nonce:new Uint8Array(16),n:0,port:channel.port2},[channel.port2]);
      };
    });
  } finally {
    clearTimeout(timer);
    channel.port1.close();
    worker.terminate();
  }
});

Deno.test('coordinator handles memory growth and an unaligned proof descriptor', async()=>{
  const moduleURL=new URL('./lib-min.mjs',import.meta.url).href;
  const source=`
    const instantiate=WebAssembly.instantiateStreaming;
    WebAssembly.instantiateStreaming=async(...args)=>{
      const result=await instantiate(...args);
      const original=result.instance.exports;
      return {...result,instance:{exports:{...original,alloc_blocks(){
        const ptr=original.alloc_blocks();
        original.memory.grow(1);
        return ptr;
      },combine(...args){
        const ptr=original.combine(...args)>>>0;
        const descriptor=new Uint8Array(original.memory.buffer,ptr,8).slice();
        const unaligned=original.memory.grow(1)*65536+1;
        new Uint8Array(original.memory.buffer,unaligned,8).set(descriptor);
        return unaligned;
      }}}};
    };
    await import(${JSON.stringify(moduleURL)});
  `;
  const url=URL.createObjectURL(new Blob([source],{type:'text/javascript'}));
  const worker=new Worker(url,{type:'module',name:'growth-0'});
  let timer;
  try {
    const proof=await new Promise((resolve,reject)=>{
      timer=setTimeout(()=>reject(new Error('worker timed out')),30000);
      worker.onerror=event=>reject(new Error(event.message));
      worker.onmessage=({data})=>{
        if(data.error) reject(new Error(data.error));
        if(data.ready) worker.postMessage({hash:'growth',nonce:Uint8Array.fromHex('0b206ed758abdcb0d43c9bb3e7808495')});
        if(data.proof) resolve(data.proof);
      };
    });
    const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',proof)).toHex();
    strictEqual(hash,'be04c35e9d55d41b58f1578c2b60f487471e480b506343eb19873dda4438f277');
  } finally {
    clearTimeout(timer);
    worker.terminate();
    URL.revokeObjectURL(url);
  }
});
