// preload
const url=new URL('lib.wasm',import.meta.url);
await(await fetch(url)).arrayBuffer();
const isWorker=!!globalThis.WorkerGlobalScope&&globalThis instanceof WorkerGlobalScope;
/**
 * @param {Uint8Array} nonce
 * @param {AbortSignal} signal
 * @param {(i:number)=>void} onProgress
 * @return {Promise<Uint8Array>}
 */
const pow=async(nonce,signal,onProgress)=>{
  const random=crypto.getRandomValues(new Uint8Array(16));
  const hash=new Uint8Array(await crypto.subtle.digest('SHA-256',random)).toHex();
  const worker=await new Promise((resolve,reject)=>{
    const worker=new Worker(import.meta.url,{type:'module',credentials:'omit',name:`${hash}-0`});
    worker.onerror=_=>reject();
    worker.onmessage=({data})=>{
      if(typeof data==='object'){
        const {hash:h,ready}=data;
        if(h===hash&&ready){
          worker.onmessage=null;
          resolve(worker);
        }
      }
    };
  });
  signal.throwIfAborted();
  let progress=0;
  return await new Promise((resolve,reject)=>{
    if(signal.aborted) return reject();
    worker.onerror=_=>{
      worker.postMessage({hash,terminate:true});
      worker.terminate();
      reject();
    }
    signal.addEventListener('abort',worker.onerror);
    worker.onmessage=({data})=>{
      if(typeof data==='object'){
        const {hash:h,proof,progress_increment:increment,progress_value:value,progress_max:max}=data;
        if(h===hash&&proof){
          worker.terminate();
          resolve(proof);
        }else if(h===hash&&max){
          const p0=progress;
          const p=Math.trunc((value?progress=value:progress+=increment)*100/max);
          if(p!==Math.trunc(p0*100/max)){
            onProgress(p/100);
          }
        }
      }
    };
    worker.postMessage({hash,nonce});
  });
};
export default pow;
if(isWorker){
  const [hash,n]=globalThis.name.split('-');
  let wasm;
  let progress_max;
  const{instance}=await WebAssembly.instantiateStreaming(fetch(url,{cache:'force-cache'}),{js:{
    println:(ptr,len)=>console.log(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,ptr,len))),
    eprintln:(ptr,len)=>console.error(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,ptr,len))),
    increment_progress:i=>postMessage({hash,progress_increment:i,progress_max}),
  }});
  wasm=instance.exports;
  const HASH_LENGTH=new DataView(wasm.memory.buffer,wasm.HASH_LENGTH_PTR,4).getUint32(0,true);
  const STEP_COUNT=new DataView(wasm.memory.buffer,wasm.STEP_COUNT_PTR,4).getUint32(0,true);
  const BLOCK_SIZE=new DataView(wasm.memory.buffer,wasm.BLOCK_SIZE_PTR,4).getUint32(0,true);
  const CHAIN_BLOCK_COUNT=new DataView(wasm.memory.buffer,wasm.CHAIN_BLOCK_COUNT_PTR,4).getUint32(0,true);
  const CHAIN_COUNT=new DataView(wasm.memory.buffer,wasm.CHAIN_COUNT_PTR,4).getUint32(0,true);
  const ITERATION_COUNT=new DataView(wasm.memory.buffer,wasm.ITERATION_COUNT_PTR,4).getUint32(0,true);
  // expected time:
  // chains: t1 -> progress = 256
  // hash chain: t2 = t1 / (4 * ITERATION_COUNT**.35)
  // state + root: t3 = t2
  // parent blocks: t4 = t2 / 2
  // reference blocks: t5 = t2 / 2
  // total: t1 + (t2 * 3)
  const t1=256;
  const t2=t1/(4*ITERATION_COUNT**.35);
  progress_max=t1+(t2*3);
  if(n==='0'){ // coordinator worker
    const initWorker=i=>new Promise((resolve,reject)=>{
      const worker=new Worker(import.meta.url,{type:'module',credentials:'omit',name:`${hash}-${i}`});
      worker.onerror=_=>reject();
      worker.onmessage=({data})=>{
        if(typeof data==='object'){
          const {hash:h,ready}=data;
          if(h===hash&&ready){
            worker.onmessage=({data:{hash:h,progress_increment,progress_value,progress_max}})=>{
              if(h===hash&&progress_max){
                postMessage({hash,progress_increment,progress_value,progress_max});
              }
            };
            resolve(worker);
          }
        }
      };
    });
    const workers=Promise.all(Array.from({length:CHAIN_COUNT},(_,i)=>initWorker(i+1)));
    onmessage=async({data})=>{
      if(typeof data==='object'){
        const {hash:h,terminate,nonce}=data;
        if(h===hash){
          if(terminate){
            (await workers).forEach(it=>it.terminate());
            return globalThis.terminate();
          }
          if(nonce instanceof Uint8Array){
            if(nonce.length!==16) throw new Error('nonce must be 16 bytes long');
            const results=await Promise.all((await workers).map((worker,n)=>new Promise((resolve,reject)=>{
              worker.onerror=_=>reject();
              const channel=new MessageChannel();
              channel.port1.onmessage=({data})=>{
                channel.port1.onmessage=null;
                resolve({hashChain:data,worker,channel});
              }
              worker.postMessage({hash,nonce,n,port:channel.port2},[channel.port2]);
            }))).catch(onerror);
            postMessage({hash,progress_value:t1+t2,progress_max});
            const hashChainsPtr=wasm.alloc_hash_chains();
            results.forEach(({hashChain}, i)=>{
              const hashChainPtr=wasm.alloc_hash_chain();
              new Uint8Array(wasm.memory.buffer,hashChainPtr,CHAIN_BLOCK_COUNT*HASH_LENGTH).set(hashChain);
              new DataView(wasm.memory.buffer,hashChainsPtr+i*4).setUint32(0,hashChainPtr,true);
            });
            const statePtr=wasm.build_state(hashChainsPtr);
            const rootPtr=wasm.root(statePtr);
            postMessage({hash,progress_value:t1+t2*2,progress_max});
            const indicesPtr=wasm.select_indices(rootPtr);
            const indices=new Uint32Array(wasm.memory.buffer,indicesPtr,STEP_COUNT);
            const parentBlocksPtr=wasm.alloc_blocks();
            const parentBlocks=new Uint8Array(wasm.memory.buffer,parentBlocksPtr,STEP_COUNT*BLOCK_SIZE);
            for(let i=0;i<STEP_COUNT;++i){
              const parentIndex=indices[i]-1;
              const j=Math.trunc(parentIndex/CHAIN_BLOCK_COUNT);
              const {worker,channel}=results[j];
              const index=parentIndex%CHAIN_BLOCK_COUNT;
              const block=await new Promise(resolve=>{
                channel.port1.onmessage=({data})=>{
                  channel.port1.onmessage=null;
                  resolve(data);
                }
                worker.postMessage({hash,index});
              });
              parentBlocks.set(block,i*BLOCK_SIZE);
            }
            postMessage({hash,progress_value:t1+t2*2.5,progress_max});
            const referenceIndicesPtr=wasm.select_reference_indices(indicesPtr,parentBlocksPtr);
            const referenceIndices=new Uint32Array(wasm.memory.buffer,referenceIndicesPtr,STEP_COUNT);
            const referenceBlocksPtr=wasm.alloc_blocks();
            const referenceBlocks=new Uint8Array(wasm.memory.buffer,referenceBlocksPtr,STEP_COUNT*BLOCK_SIZE);
            for(let i=0;i<STEP_COUNT;++i){
              const referenceIndex=referenceIndices[i];
              const j=Math.trunc(referenceIndex/CHAIN_BLOCK_COUNT);
              const {worker,channel}=results[j];
              const index=referenceIndex%CHAIN_BLOCK_COUNT;
              const block=await new Promise(resolve=>{
                channel.port1.onmessage=({data})=>{
                  channel.port1.onmessage=null;
                  resolve(data);
                }
                worker.postMessage({hash,index});
              });
              referenceBlocks.set(block,i*BLOCK_SIZE);
            }
            (await workers).forEach(it=>it.terminate());
            const ptrAndLenPtr=wasm.combine(statePtr,rootPtr,indicesPtr,referenceIndicesPtr,parentBlocksPtr,referenceBlocksPtr);
            const [ptr,len]=new Uint32Array(wasm.memory.buffer,ptrAndLenPtr,2);
            const proof=new Uint8Array(wasm.memory.buffer,ptr,len);
            postMessage({hash,progress_value:progress_max,progress_max});
            postMessage({hash,proof});
          }
        }
      }
    }
  }else{ // chain worker
    let chainPtr=undefined;
    let port=undefined;
    onmessage=async({data})=>{
      if(typeof data==='object'){
        const {hash:h,terminate,nonce,n,port:p,index}=data;
        if(h===hash){
          if(terminate){
            return globalThis.terminate();
          }
          if(p&&nonce instanceof Uint8Array){
            const i=parseInt(n);
            if(nonce.length!==16||isNaN(i)||i<0||i>=CHAIN_COUNT) throw new Error();
            port=p;
            const noncePtr=wasm.alloc_nonce();
            new Uint8Array(wasm.memory.buffer,noncePtr,16).set(nonce);
            chainPtr=wasm.generate_chain(i,noncePtr);
            wasm.free_nonce(noncePtr, 16);
            const hashChainPtr=wasm.hash_chain(chainPtr);
            const hashChain=new Uint8Array(wasm.memory.buffer,hashChainPtr,CHAIN_BLOCK_COUNT*HASH_LENGTH);
            port.postMessage(hashChain);
          }else if(!isNaN(index)&&index>0&&index<CHAIN_BLOCK_COUNT){
            port.postMessage(new Uint8Array(wasm.memory.buffer,chainPtr+index*BLOCK_SIZE,BLOCK_SIZE));
          }
        }
      }
    };
  }
  postMessage({hash,ready:true});
}
