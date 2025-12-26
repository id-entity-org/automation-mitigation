// preload
const url=new URL('lib.wasm',import.meta.url);
await(await fetch(url)).arrayBuffer();
let wasm;
const{instance}=await WebAssembly.instantiateStreaming(fetch(url,{cache:'force-cache'}),{js:{
  println:(ptr,len)=>console.log(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,ptr,len))),
  eprintln:(ptr,len)=>console.error(new TextDecoder().decode(new Uint8Array(wasm.memory.buffer,ptr,len))),
}});
wasm=instance.exports;
const BLOCK_SIZE=256;
const CHAIN_BLOCK_COUNT=524_288;
const generateChain=(i,nonce)=>{
  new Uint8Array(wasm.memory.buffer,0,16).set(nonce);
  const ptr=wasm.generate_chain(i,0);
  console.log(ptr);
  return new Uint8Array(wasm.memory.buffer,ptr,BLOCK_SIZE*CHAIN_BLOCK_COUNT);
};
const freeChain=chain=>{
  wasm.free_chain(chain.byteOffset);
}
const generateChainPrealloc=(i,nonce)=>{
  wasm.memory.grow(Math.ceil((BLOCK_SIZE*CHAIN_BLOCK_COUNT+16) / 65536));
  new Uint8Array(wasm.memory.buffer,0,16).set(nonce);
  const chain=new Uint8Array(wasm.memory.buffer,16,BLOCK_SIZE*CHAIN_BLOCK_COUNT);
  wasm.generate_chain_prealloc(i,0,16);
  return chain;
};
export{generateChain,freeChain,generateChainPrealloc};
