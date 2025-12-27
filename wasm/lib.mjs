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
  const noncePointer=wasm.malloc(16);
  new Uint8Array(wasm.memory.buffer,noncePointer,16).set(nonce);
  const chainPointer=wasm.generate_chain(i,noncePointer);
  wasm.free(noncePointer);
  return new Uint8Array(wasm.memory.buffer,chainPointer,BLOCK_SIZE*CHAIN_BLOCK_COUNT);
};
const freeChain=chain=>{
  wasm.freeChain(chain.byteOffset);
}
const combineChains=(chain1,chain2)=>{
  const res=wasm.combine_chains(chain1.byteOffset,chain2.byteOffset);
  
};
export{generateChain,freeChain};
